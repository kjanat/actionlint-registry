package validation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"actionlint.kjanat.dev/v2/internal/checking"
	"actionlint.kjanat.dev/v2/internal/input/references"
	"actionlint.kjanat.dev/v2/internal/input/workspace"
	"actionlint.kjanat.dev/v2/internal/model/lifecycle"
	"actionlint.kjanat.dev/v2/internal/model/rule"
	"actionlint.kjanat.dev/v2/internal/model/runners"
	"actionlint.kjanat.dev/v2/internal/model/runners/runnerapi"
	"actionlint.kjanat.dev/v2/internal/model/scriptengine"
	"actionlint.kjanat.dev/v2/internal/plugins/pluginexecution/component"
)

func validateScriptEngine(ctx context.Context, plugin *component.Plugin, metadata embeddedMetadata) (roleEvidence, error) {
	descriptor := plugin.ScriptDescriptor()
	if descriptor.ID != metadata.ID {
		return roleEvidence{}, errors.New("embedded metadata identity differs from runtime descriptor")
	}
	names, err := ruleNames([]rule.Descriptor{descriptor.Rule})
	if err != nil {
		return roleEvidence{}, err
	}
	registration := descriptor.Rule
	if registration.Name == "ruff" || registration.Name == "shellcheck" {
		registration.Name = "registry-fixture"
	}
	if _, err := workflowInputWithDescriptor(ctx, sampleWorkflow, registration); err != nil {
		return roleEvidence{}, fmt.Errorf("engine registration: %w", err)
	}
	if err := plugin.ValidateConfig(ctx, nil); err != nil {
		return roleEvidence{}, fmt.Errorf("default configuration: %w", err)
	}
	request := scriptengine.Request{Source: "x\n", Filename: "registry-smoke.txt"}
	if slices.Contains(descriptor.Shells, "python") || descriptor.Engine == "ruff" {
		request.Source, request.Filename = "print(missing)\n", "registry-smoke.py"
	}
	for attempt := range 2 {
		findings, err := plugin.Check(ctx, request)
		if err != nil {
			return roleEvidence{}, fmt.Errorf("sample invocation %d: %w", attempt+1, err)
		}
		if err := scriptFindings(findings, request); err != nil {
			return roleEvidence{}, err
		}
		if descriptor.Engine == "ruff" && !slices.ContainsFunc(findings, func(d scriptengine.Diagnostic) bool { return d.Code == "F821" }) {
			return roleEvidence{}, errors.New("ruff smoke sample did not report F821")
		}
	}
	return roleEvidence{rules: names, checks: []string{"script-engine", "rule-descriptors", "application-registration", "default-config", "repeated-sample", "diagnostic-ranges"}}, nil
}

const runnerWorkflow = "name: Registry runner smoke\non: push\njobs:\n  smoke:\n    runs-on: registry-smoke\n    steps:\n      - run: echo ok\n"
const runnerScope = "registry-smoke"

func checkRunnerProvider(ctx context.Context, registration runnerapi.Registration, declared *runnerDeclaration, asOf lifecycle.Date) (roleEvidence, error) {
	descriptor := registration.Provider.RunnerDescriptor()
	if declared != nil {
		if err := declared.matches(descriptor); err != nil {
			return roleEvidence{}, err
		}
	}
	for _, builtin := range []runnerapi.Provider{runners.GitHubProvider(runners.KnownLabels(nil)), runners.SnapshotProvider()} {
		reserved := builtin.RunnerDescriptor()
		if reserved.Name != descriptor.Name {
			continue
		}
		if target := slices.IndexFunc(descriptor.Targets, func(target string) bool { return slices.Contains(reserved.Targets, target) }); target >= 0 {
			return roleEvidence{}, fmt.Errorf("runner provider name %q is reserved by actionlint's built-in provider for target %q", descriptor.Name, descriptor.Targets[target])
		}
	}
	// A generic checker has no vendor dataset. Missing evidence must still produce
	// a valid answer for each selector, without fetching resources during analysis.
	for _, target := range descriptor.Targets {
		options := checking.Options{
			Runners: runnerapi.Options{AsOf: asOf, Target: target, Provider: descriptor.Name, Scope: runnerScope,
				Snapshot: runnerapi.RunnerSnapshot{Scope: runnerScope, Freshness: runnerapi.Missing}, Providers: []runnerapi.Registration{registration}}}
		for attempt := range 2 {
			if _, err := checking.Analyze(ctx, options, []workspace.InputFile{{Path: samplePath, Content: []byte(runnerWorkflow)}}); err != nil {
				return roleEvidence{}, fmt.Errorf("runner invocation %d: %w", attempt+1, err)
			}
		}
	}
	return roleEvidence{rules: []string{}, checks: []string{"runner-provider", "runner-descriptor", "missing-snapshot", "host-resolution", "repeated-sample"}}, nil
}

const resolverRepository = "registry/smoke"

type resolverRepositoryAccess struct{ object string }

func (access resolverRepositoryAccess) Open(context.Context, references.Request) (references.RepositorySession, error) {
	return resolverRepositorySession(access), nil
}

type resolverRepositorySession struct{ object string }

func (session resolverRepositorySession) Repository() references.RepositoryIdentity {
	return references.RepositoryIdentity{Host: "github.com", Name: resolverRepository, ObservedAt: "2026-01-01T00:00:00Z"}
}

func (resolverRepositorySession) Reference(context.Context, string) (string, bool, error) {
	return "", false, nil
}

func (session resolverRepositorySession) Object(_ context.Context, id string) (references.RepositoryObject, bool, error) {
	return references.RepositoryCommit{}, id == session.object, nil
}

func (resolverRepositorySession) Finish(context.Context) (json.RawMessage, error) {
	return json.RawMessage(`{"source":"registry-smoke"}`), nil
}

func validateReferenceResolver(ctx context.Context, plugin *component.Plugin) (roleEvidence, error) {
	commit := strings.Repeat("a", 40)
	request := references.Request{Version: 1, Repository: resolverRepository, Ref: commit, Kind: "action"}
	for attempt := range 2 {
		result, err := plugin.Resolve(references.WithRepositoryAccess(ctx, resolverRepositoryAccess{object: commit}), request)
		if err != nil {
			return roleEvidence{}, fmt.Errorf("resolution %d: %w", attempt+1, err)
		}
		if err := references.ValidateResult(request, result); err != nil {
			return roleEvidence{}, fmt.Errorf("resolution %d: %w", attempt+1, err)
		}
		if result.Commit != commit {
			return roleEvidence{}, fmt.Errorf("resolution %d selected %q instead of the requested commit", attempt+1, result.Commit)
		}
	}
	return roleEvidence{rules: []string{}, checks: []string{"reference-resolver", "repeated-sample"}}, nil
}
