package validation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	checking "actionlint.kjanat.dev/v2/internal/checking"
	checkinputs "actionlint.kjanat.dev/v2/internal/checking/inputs"
	rule "actionlint.kjanat.dev/v2/internal/checking/rules"
	"actionlint.kjanat.dev/v2/internal/checking/scripts/registry"
	"actionlint.kjanat.dev/v2/internal/input/workspace"
	componenthost "actionlint.kjanat.dev/v2/internal/plugins/execution/component"
	results "actionlint.kjanat.dev/v2/internal/results"
)

const sampleWorkflow = "name: Registry smoke\non: push\njobs:\n  smoke:\n    runs-on: ubuntu-latest\n    steps:\n      - id: sample\n        shell: bash\n        run: |\n          printf '%s\\n' $value\n"
const emptyWorkflow = "name: Registry empty\non: push\njobs: {}\n"
const samplePath = "registry-smoke.yml"

func validateComponent(ctx context.Context, path string, metadata embeddedMetadata) (result Result, err error) {
	component, err := componenthost.Load(ctx, path, componenthost.Options{Timeout: callTimeout, MemoryPages: 1024, ReservedRules: checking.BuiltinRuleNames()})
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, component.Close(context.WithoutCancel(ctx))) }()
	switch metadata.Interface {
	case scriptInterface:
		return validateScriptComponent(ctx, component)
	case runnerInterface:
		return validateRunnerComponent(ctx, component, metadata)
	}
	if !component.HasAnalyzer() {
		return result, errors.New("component does not implement its declared analyzer role")
	}
	descriptor := component.Descriptor()
	declared, err := decodeDescriptor[componentDeclaration](metadata.Descriptor)
	if err != nil {
		return result, err
	}
	if err := declared.matches(descriptor); err != nil {
		return result, err
	}
	names, err := ruleNames([]rule.Descriptor{descriptor.Descriptor})
	if err != nil {
		return result, err
	}
	for attempt := range 2 {
		findings, err := analyzeComponent(ctx, component, sampleWorkflow, names)
		if err != nil {
			return result, fmt.Errorf("sample invocation %d: %w", attempt+1, err)
		}
		if descriptor.Name == "shellcheck" && !slices.ContainsFunc(findings, func(d results.Diagnostic) bool { return d.Code == "SC2086" }) {
			return result, errors.New("shellcheck smoke sample did not report SC2086")
		}
	}
	_, err = runComponentCheck(ctx, component, emptyWorkflow, names)
	if err != nil {
		return result, fmt.Errorf("empty workflow: %w", err)
	}
	return Result{Kind: "component", PluginID: metadata.ID, Rules: names,
		Checks: []string{"host-wit-contract", "rule-descriptors", "application-registration", "default-config", "repeated-sample", "diagnostic-ranges", "empty-workflow"}, HostCommit: HostCommit}, nil
}

type checkedAnalyzer struct {
	checkinputs.Checker
	rules    []string
	findings []results.Diagnostic
	called   bool
}

type checkedToolAnalyzer struct {
	*checkedAnalyzer
	checkinputs.ToolIntegrator
}

func (checked *checkedAnalyzer) CheckDocument(ctx context.Context, input checkinputs.Input) ([]results.Diagnostic, error) {
	checked.called = true
	findings, err := checked.Checker.CheckDocument(ctx, input)
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
func analyzeComponent(ctx context.Context, component checkinputs.Checker, content string, names []string) ([]results.Diagnostic, error) {
	checked, err := runComponentCheck(ctx, component, content, names)
	if err != nil {
		return nil, err
	}
	if !checked.called {
		return nil, errors.New("application did not invoke component")
	}
	return checked.findings, nil
}

func runComponentCheck(ctx context.Context, component checkinputs.Checker, content string, names []string) (*checkedAnalyzer, error) {
	checked := &checkedAnalyzer{Checker: component, rules: names}
	options := checking.Options{Analyzers: []checkinputs.Registration{{Checker: checked}}}
	if integrator, ok := component.(checkinputs.ToolIntegrator); ok && integrator.ToolIntegration() != nil {
		tool := integrator.ToolIntegration().Tool
		if !slices.Contains(registry.IDs(), tool) {
			return nil, fmt.Errorf("unsupported tool integration %q", tool)
		}
		options.Tools = registry.Registrations(registry.Selections{tool: {Command: tool, ManagedOnly: true}})
		options.Analyzers[0].Checker = checkedToolAnalyzer{checkedAnalyzer: checked, ToolIntegrator: integrator}
	}
	_, err := checking.Analyze(ctx,
		options,
		[]workspace.Source{{Path: samplePath, Content: []byte(content)}},
	)
	if err != nil {
		return nil, err
	}
	return checked, nil
}

type inputCollector struct {
	input      *checkinputs.Input
	descriptor rule.Descriptor
}

func (collector *inputCollector) Descriptor() checkinputs.Descriptor {
	descriptor := collector.descriptor.Clone()
	descriptor.RequiredInputs = []rule.InputKind{rule.Source, rule.Scripts, rule.Mappings, rule.Invocations, rule.Execution, rule.Dependencies}
	return checkinputs.Descriptor{Descriptor: descriptor}
}

func (collector *inputCollector) CheckDocument(_ context.Context, input checkinputs.Input) ([]results.Diagnostic, error) {
	collector.input = &input
	return nil, nil
}

func workflowInput(ctx context.Context, content string) (checkinputs.Input, error) {
	return workflowInputWithSchema(ctx, content, nil)
}

func workflowInputWithSchema(ctx context.Context, content string, schema json.RawMessage) (checkinputs.Input, error) {
	return workflowInputWithDescriptor(ctx, content, rule.Descriptor{Name: "registry-fixture", Description: "Collect shared workflow facts", Category: "correctness", OptionsSchema: schema})
}

func workflowInputWithDescriptor(ctx context.Context, content string, descriptor rule.Descriptor) (checkinputs.Input, error) {
	collector := &inputCollector{descriptor: descriptor}
	_, err := checking.Analyze(ctx,
		checking.Options{Analyzers: []checkinputs.Registration{{Checker: collector}}},
		[]workspace.Source{{Path: samplePath, Content: []byte(content)}},
	)
	if err != nil {
		return checkinputs.Input{}, err
	}
	if collector.input == nil {
		return checkinputs.Input{}, errors.New("host did not produce workflow facts")
	}
	return *collector.input, nil
}
