package validation

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"actionlint.kjanat.dev/v2/internal/checking"
	"actionlint.kjanat.dev/v2/internal/input/workspace"
	"actionlint.kjanat.dev/v2/internal/model/lifecycle"
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

func validateRunnerComponent(ctx context.Context, plugin *component.Plugin, metadata embeddedMetadata, asOf lifecycle.Date) (Result, error) {
	if !plugin.HasRunnerProvider() {
		return Result{}, errors.New("component does not implement its declared runner-provider role")
	}
	return checkRunnerProvider(ctx, runnerapi.Registration{Provider: plugin, ImplementationID: plugin.ArtifactDigest()}, metadata, asOf)
}

const runnerWorkflow = "name: Registry runner smoke\non: push\njobs:\n  smoke:\n    runs-on: registry-smoke\n    steps:\n      - run: echo ok\n"
const runnerScope = "registry-smoke"

func checkRunnerProvider(ctx context.Context, registration runnerapi.Registration, metadata embeddedMetadata, asOf lifecycle.Date) (Result, error) {
	descriptor := registration.Provider.RunnerDescriptor()
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
		options := checking.Options{
			Runners: runnerapi.Options{AsOf: asOf, Target: target, Provider: descriptor.Name, Scope: runnerScope,
				Snapshot: runnerapi.RunnerSnapshot{Scope: runnerScope, Freshness: runnerapi.Missing}, Providers: []runnerapi.Registration{registration}}}
		for attempt := range 2 {
			if _, err := checking.Analyze(ctx, options, []workspace.InputFile{{Path: samplePath, Content: []byte(runnerWorkflow)}}); err != nil {
				return Result{}, fmt.Errorf("runner invocation %d: %w", attempt+1, err)
			}
		}
	}
	return Result{Kind: "component", PluginID: metadata.ID, Rules: []string{}, HostCommit: HostCommit, RunnerAsOf: asOf.String(),
		Checks: []string{"host-wit-contract", "runner-provider", "runner-descriptor", "missing-snapshot", "host-resolution", "repeated-sample"}}, nil
}
