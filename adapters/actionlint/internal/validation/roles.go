package validation

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"actionlint.kjanat.dev/v2/internal/base/sourcetext"
	"actionlint.kjanat.dev/v2/internal/model/rule"
	"actionlint.kjanat.dev/v2/internal/model/runners/runnerapi"
	"actionlint.kjanat.dev/v2/internal/model/scriptengine"
	"actionlint.kjanat.dev/v2/internal/plugins/pluginexecution/component"
)

func validateScriptComponent(ctx context.Context, plugin *component.Plugin) (Result, error) {
	if !plugin.HasScriptEngine() {
		return Result{}, errors.New("component does not implement its declared script-engine role")
	}
	descriptor := plugin.ScriptDescriptor()
	names, err := ruleNames([]rule.Descriptor{descriptor.Rule})
	if err != nil {
		return Result{}, err
	}
	registration := descriptor.Rule
	if registration.Name == "ruff" || registration.Name == "shellcheck" {
		registration.Name = "registry-fixture"
	}
	if _, err := workflowInputWithDescriptor(ctx, sampleWorkflow, registration); err != nil {
		return Result{}, fmt.Errorf("engine registration: %w", err)
	}
	if err := plugin.ValidateConfig(ctx, nil); err != nil {
		return Result{}, fmt.Errorf("default configuration: %w", err)
	}
	request := scriptengine.Request{Source: "x\n", Filename: "registry-smoke.txt"}
	if slices.Contains(descriptor.Shells, "python") || descriptor.Engine == "ruff" {
		request.Source, request.Filename = "print(missing)\n", "registry-smoke.py"
	}
	for attempt := range 2 {
		findings, err := plugin.Check(ctx, request)
		if err != nil {
			return Result{}, fmt.Errorf("sample invocation %d: %w", attempt+1, err)
		}
		if err := scriptFindings(findings, request); err != nil {
			return Result{}, err
		}
		if descriptor.Engine == "ruff" && !slices.ContainsFunc(findings, func(d scriptengine.Diagnostic) bool { return d.Code == "F821" }) {
			return Result{}, errors.New("ruff smoke sample did not report F821")
		}
	}
	return Result{Kind: "component", PluginID: descriptor.ID, Rules: names, HostCommit: HostCommit,
		Checks: []string{"host-wit-contract", "script-engine", "rule-descriptors", "application-registration", "default-config", "repeated-sample", "diagnostic-ranges"}}, nil
}

func validateRunnerComponent(ctx context.Context, plugin *component.Plugin, metadata embeddedMetadata) (Result, error) {
	if !plugin.HasRunnerProvider() {
		return Result{}, errors.New("component does not implement its declared runner-provider role")
	}
	descriptor := plugin.RunnerDescriptor()
	declared, err := decodeDescriptor[runnerDeclaration](metadata.Descriptor)
	if err != nil {
		return Result{}, err
	}
	if err := declared.matches(descriptor); err != nil {
		return Result{}, err
	}
	// A generic checker has no vendor dataset. Missing evidence must still produce
	// a valid answer for each selector, without fetching resources during analysis.
	for _, target := range descriptor.Targets {
		request := runnerapi.Request{Target: target, Scope: "registry-smoke", Snapshot: runnerapi.RunnerSnapshot{Scope: "registry-smoke", Freshness: runnerapi.Missing},
			Selectors: []runnerapi.Selector{{Labels: []runnerapi.Constraint{{Value: runnerapi.Literal("registry-smoke"), Position: sourcetext.Position{Line: 1, Column: 1}}}}}}
		for attempt := range 2 {
			response, err := plugin.ResolveRunners(ctx, request)
			if err != nil {
				return Result{}, fmt.Errorf("runner invocation %d: %w", attempt+1, err)
			}
			if len(response.Answers) != len(request.Selectors) {
				return Result{}, errors.New("runner returned the wrong answer count")
			}
		}
	}
	return Result{Kind: "component", PluginID: metadata.ID, Rules: []string{}, HostCommit: HostCommit,
		Checks: []string{"host-wit-contract", "runner-provider", "runner-descriptor", "missing-snapshot", "repeated-sample"}}, nil
}
