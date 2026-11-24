package validation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	checking "actionlint.kjanat.dev/v2/internal/checking"
	"actionlint.kjanat.dev/v2/internal/checking/scriptanalysis/registry"
	"actionlint.kjanat.dev/v2/internal/input/workspace"
	"actionlint.kjanat.dev/v2/internal/model/checkinputs"
	"actionlint.kjanat.dev/v2/internal/model/lifecycle"
	"actionlint.kjanat.dev/v2/internal/model/rule"
	"actionlint.kjanat.dev/v2/internal/model/runners/runnerapi"
	pluginartifact "actionlint.kjanat.dev/v2/internal/plugins/artifacts"
	"actionlint.kjanat.dev/v2/internal/plugins/pluginexecution/component"
	results "actionlint.kjanat.dev/v2/internal/results"
)

const sampleWorkflow = "name: Registry smoke\non: push\njobs:\n  smoke:\n    runs-on: ubuntu-latest\n    steps:\n      - id: sample\n        shell: bash\n        run: |\n          printf '%s\\n' $value\n"
const emptyWorkflow = "name: Registry empty\non: push\njobs: {}\n"
const samplePath = "registry-smoke.yml"

var componentOptions = component.Options{ReservedRules: checking.BuiltinRuleNames(), Timeout: callTimeout, MemoryPages: 1024}

func loadComponent(ctx context.Context, path string) (*component.Plugin, error) {
	return component.LoadComponentPlugin(ctx, path, componentOptions)
}

type roleEvidence struct {
	rules  []string
	checks []string
}

func validateComponent(ctx context.Context, artifact *pluginartifact.Artifact, metadata embeddedMetadata, asOf lifecycle.Date) (result Result, err error) {
	roles, err := component.Admit(ctx, component.ComponentBytes(artifact.Bytes))
	if err != nil {
		return result, err
	}
	plugin, err := component.LoadArtifact(ctx, artifact, componentOptions)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, plugin.Close(context.WithoutCancel(ctx))) }()
	result = Result{Kind: "component", PluginID: metadata.ID, Rules: []string{}, Checks: []string{"host-wit-contract"}, HostCommit: HostCommit}
	add := func(evidence roleEvidence, err error) error {
		if err != nil {
			return err
		}
		result.Rules = append(result.Rules, evidence.rules...)
		for _, name := range evidence.checks {
			if !slices.Contains(result.Checks, name) {
				result.Checks = append(result.Checks, name)
			}
		}
		return nil
	}
	if roles.Analyzer != "" {
		if err := add(validateAnalyzer(ctx, plugin, metadata, metadata.Interface == roles.Analyzer)); err != nil {
			return Result{}, err
		}
	}
	if roles.ScriptEngine != "" {
		if err := add(validateScriptEngine(ctx, plugin, metadata)); err != nil {
			return Result{}, err
		}
	}
	if roles.Runner != "" {
		var declared *runnerDeclaration
		if metadata.Interface == roles.Runner {
			descriptor, err := decodeDescriptor[runnerDeclaration](metadata.Descriptor)
			if err != nil {
				return Result{}, err
			}
			declared = &descriptor
		}
		registration := runnerapi.Registration{Provider: plugin, ImplementationID: plugin.ArtifactDigest()}
		if err := add(checkRunnerProvider(ctx, registration, declared, asOf)); err != nil {
			return Result{}, err
		}
		result.RunnerAsOf = asOf.String()
	}
	if roles.ReferenceResolver != "" {
		if err := add(validateReferenceResolver(ctx, plugin)); err != nil {
			return Result{}, err
		}
	}
	slices.Sort(result.Rules)
	result.Rules = slices.Compact(result.Rules)
	return result, nil
}

func validateAnalyzer(ctx context.Context, plugin *component.Plugin, metadata embeddedMetadata, declaredRole bool) (roleEvidence, error) {
	descriptor := plugin.Descriptor()
	if declaredRole {
		declared, err := decodeDescriptor[componentDeclaration](metadata.Descriptor)
		if err != nil {
			return roleEvidence{}, err
		}
		if err := declared.matches(descriptor); err != nil {
			return roleEvidence{}, err
		}
	}
	names, err := ruleNames([]rule.Descriptor{descriptor.Descriptor})
	if err != nil {
		return roleEvidence{}, err
	}
	for attempt := range 2 {
		findings, err := analyzeComponent(ctx, plugin, sampleWorkflow, names)
		if err != nil {
			return roleEvidence{}, fmt.Errorf("sample invocation %d: %w", attempt+1, err)
		}
		if descriptor.Name == "shellcheck" && !slices.ContainsFunc(findings, func(d results.Diagnostic) bool { return d.Code == "SC2086" }) {
			return roleEvidence{}, errors.New("shellcheck smoke sample did not report SC2086")
		}
	}
	if _, err := runComponentCheck(ctx, plugin, emptyWorkflow, names); err != nil {
		return roleEvidence{}, fmt.Errorf("empty workflow: %w", err)
	}
	return roleEvidence{rules: names, checks: []string{"rule-descriptors", "application-registration", "default-config", "repeated-sample", "diagnostic-ranges", "empty-workflow"}}, nil
}

type checkedAnalyzer struct {
	results.Analyzer
	rules    []string
	findings []results.Diagnostic
	called   bool
}

type checkedToolAnalyzer struct {
	*checkedAnalyzer
	checkinputs.ToolIntegrator
}

func (checked *checkedAnalyzer) AnalyzeDocument(ctx context.Context, input checkinputs.AnalyzerInput) ([]results.Diagnostic, error) {
	checked.called = true
	findings, err := checked.Analyzer.AnalyzeDocument(ctx, input)
	if err != nil {
		return nil, err
	}
	if err := componentFindings(findings, input, checked.rules); err != nil {
		return nil, err
	}
	checked.findings = findings
	return findings, nil
}

// Use the host checking pipeline so option validation, rule-name collisions and
// required inputs follow the same path as ordinary checks.
func analyzeComponent(ctx context.Context, analyzer results.Analyzer, content string, names []string) ([]results.Diagnostic, error) {
	checked, err := runComponentCheck(ctx, analyzer, content, names)
	if err != nil {
		return nil, err
	}
	if !checked.called {
		return nil, errors.New("application did not invoke component")
	}
	return checked.findings, nil
}

func runComponentCheck(ctx context.Context, analyzer results.Analyzer, content string, names []string) (*checkedAnalyzer, error) {
	checked := &checkedAnalyzer{Analyzer: analyzer, rules: names}
	options := checking.Options{Analyzers: []results.AnalyzerRegistration{{Analyzer: checked}}}
	if integrator, ok := analyzer.(checkinputs.ToolIntegrator); ok && integrator.ToolIntegration() != nil {
		tool := integrator.ToolIntegration().Tool
		if !slices.Contains(registry.IDs(), tool) {
			return nil, fmt.Errorf("unsupported tool integration %q", tool)
		}
		options.Tools = registry.Registrations(registry.ToolSelections{tool: {Command: tool, ManagedOnly: true}})
		options.Analyzers[0].Analyzer = checkedToolAnalyzer{checkedAnalyzer: checked, ToolIntegrator: integrator}
	}
	_, err := checking.Analyze(ctx,
		options,
		[]workspace.InputFile{{Path: samplePath, Content: []byte(content)}},
	)
	if err != nil {
		return nil, err
	}
	return checked, nil
}

type inputCollector struct {
	input      *checkinputs.AnalyzerInput
	descriptor rule.Descriptor
}

func (collector *inputCollector) Descriptor() checkinputs.Descriptor {
	descriptor := collector.descriptor.Clone()
	descriptor.RequiredInputs = []rule.InputKind{rule.Source, rule.Scripts, rule.Mappings, rule.Invocations, rule.Execution, rule.Dependencies}
	return checkinputs.Descriptor{Descriptor: descriptor}
}

func (collector *inputCollector) AnalyzeDocument(_ context.Context, input checkinputs.AnalyzerInput) ([]results.Diagnostic, error) {
	collector.input = &input
	return nil, nil
}

func workflowInput(ctx context.Context, content string) (checkinputs.AnalyzerInput, error) {
	return workflowInputWithSchema(ctx, content, nil)
}

func workflowInputWithSchema(ctx context.Context, content string, schema json.RawMessage) (checkinputs.AnalyzerInput, error) {
	return workflowInputWithDescriptor(ctx, content, rule.Descriptor{Name: "registry-fixture", Description: "Collect shared workflow facts", Category: "correctness", OptionsSchema: schema})
}

func workflowInputWithDescriptor(ctx context.Context, content string, descriptor rule.Descriptor) (checkinputs.AnalyzerInput, error) {
	collector := &inputCollector{descriptor: descriptor}
	_, err := checking.Analyze(ctx,
		checking.Options{Analyzers: []results.AnalyzerRegistration{{Analyzer: collector}}},
		[]workspace.InputFile{{Path: samplePath, Content: []byte(content)}},
	)
	if err != nil {
		return checkinputs.AnalyzerInput{}, err
	}
	if collector.input == nil {
		return checkinputs.AnalyzerInput{}, errors.New("host did not produce workflow facts")
	}
	return *collector.input, nil
}
