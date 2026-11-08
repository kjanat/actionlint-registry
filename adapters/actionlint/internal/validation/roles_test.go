package validation

import (
	runner "actionlint.kjanat.dev/v2/internal/model/runners/contract"
	"errors"
	"slices"
	"strings"
	"testing"
)

const scriptMetadata = `{"metadata_version":1,"transport":"wasm-component","id":"echo-component","name":"Echo component","description":"Registry script fixture","license":"MIT","repository":"https://github.com/example/plugin","plugin_version":"1.0.0","interface":"kjanat:actionlint/script-engine@0.2.0","wit_sha256":"c20d7e9e516166576fdf19bfd86e0843838179b12ad55350c33db8d04c2eaa9b","engine":{"name":"echo","version":"1.0.0"},"capabilities":{"script_shells":["python"]},"config_schema":{"type":"object"},"rules":[{"name":"echo","description":"Find a missing value","category":"correctness","subcategory":"python","maturity":"stable","provider":"echo-component","recommended":true,"documentation_url":"https://example.com/echo","options_schema":{"type":"object"},"fix_availability":"none"}]}`
const runnerMetadata = `{"metadata_version":1,"transport":"wasm-component","id":"buildkite-runners","name":"Buildkite runners","description":"Registry runner fixture","license":"MIT","repository":"https://github.com/example/plugin","plugin_version":"1.0.0","interface":"kjanat:actionlint/runner-provider@0.2.0","wit_sha256":"2a995ebe267d4d5df5664c0f6f48b40cc770116ef9375935f26f3a648652df9f","descriptor":{"name":"buildkite-runners","version":"0.1.0","targets":["buildkite"]}}`

// Components implementing only one extension role must reach that role's runtime
// checks; requiring an analyzer descriptor used to reject both before loading.
func TestComponentExtensionRoles(t *testing.T) {
	for _, test := range []struct{ fixture, metadata, id, check, contract string }{
		{"component-script", scriptMetadata, "echo-component", "script-engine", scriptContractDigest},
		{"component-runners", runnerMetadata, "buildkite-runners", "runner-provider", runnerContractDigest},
	} {
		t.Run(test.check, func(t *testing.T) {
			result, err := Validate(t.Context(), packagedFixture(t, test.fixture, test.metadata))
			if err != nil {
				t.Fatal(err)
			}
			if result.PluginID != test.id || !slices.Contains(result.Checks, test.check) || !strings.Contains(result.Contract, test.contract) {
				t.Fatalf("wrong role evidence: %+v", result)
			}
			if _, err := Validate(t.Context(), packagedFixture(t, "component-no-sudo", test.metadata)); err == nil {
				t.Fatal("accepted a component without its declared role")
			}
		})
	}
}

func TestScriptComponentIdentityMustMatchRuntime(t *testing.T) {
	for _, metadata := range []string{
		strings.Replace(scriptMetadata, "echo-component", "different-plugin", 1),
		strings.Replace(scriptMetadata, `"plugin_version":"1.0.0"`, `"plugin_version":"2.0.0"`, 1),
	} {
		if _, err := Validate(t.Context(), packagedFixture(t, "component-script", metadata)); err == nil {
			t.Fatal("accepted static/runtime script identity mismatch")
		}
	}
}

func TestRunnerPackageIdentityIsIndependentOfProvider(t *testing.T) {
	metadata := strings.Replace(runnerMetadata, `"id":"buildkite-runners"`, `"id":"example/queue-package"`, 1)
	metadata = strings.Replace(metadata, `"plugin_version":"1.0.0"`, `"plugin_version":"2.0.0"`, 1)
	result, err := Validate(t.Context(), packagedFixture(t, "component-runners", metadata))
	if err != nil {
		t.Fatal(err)
	}
	if result.PluginID != "example/queue-package" || result.PluginVersion != "2.0.0" || len(result.Rules) != 0 {
		t.Fatalf("runner and package identities were conflated: %+v", result)
	}
}

func TestRunnerDeclarationMustMatchRuntime(t *testing.T) {
	for _, metadata := range []string{
		strings.Replace(runnerMetadata, `"descriptor":{"name":"buildkite-runners"`, `"descriptor":{"name":"different-provider"`, 1),
		strings.Replace(runnerMetadata, `"version":"0.1.0"`, `"version":"2.0.0"`, 1),
		strings.Replace(runnerMetadata, `"targets":["buildkite"]`, `"targets":["github"]`, 1),
		strings.Replace(runnerMetadata, `"targets":["buildkite"]`, `"targets":["buildkite","github"]`, 1),
		strings.Replace(runnerMetadata, `"targets":["buildkite"]`, `"targets":["buildkite"],"ignored":true`, 1),
		strings.Replace(runnerMetadata, `"descriptor":{"name":"buildkite-runners","version":"0.1.0","targets":["buildkite"]}`, `"descriptor":null`, 1),
	} {
		if _, err := Validate(t.Context(), packagedFixture(t, "component-runners", metadata)); err == nil {
			t.Fatalf("accepted invalid runner declaration: %s", metadata)
		}
	}
}

func TestRunnerTargetOrderDoesNotChangeSupportedPlatforms(t *testing.T) {
	declared := runnerDeclaration{Name: "provider", Version: "1", Targets: []string{"buildkite", "github"}}
	actual := runner.Descriptor{Name: "provider", Version: "1", Targets: []string{"github", "buildkite"}}
	if err := declared.matches(actual); err != nil {
		t.Fatal(err)
	}
	if declared.Targets[0] != "buildkite" || actual.Targets[0] != "github" {
		t.Fatal("comparison changed its input targets")
	}
}

// Exercise the host's 0.3 runtime dispatch with real standalone and paired guests.
func TestScriptComponent03(t *testing.T) {
	for _, test := range []struct{ fixture, metadata, id string }{
		{"component-script-0.3.0", scriptMetadata03, "script-engine-0.3.0-fixture"},
		{"component-template-script-0.3.0", templateMetadata03, "template-script-engine-0.3.0-fixture"},
	} {
		t.Run(test.fixture, func(t *testing.T) {
			result, err := Validate(t.Context(), packagedFixture(t, test.fixture, test.metadata))
			if err != nil {
				t.Fatal(err)
			}
			if result.PluginID != test.id || !slices.Contains(result.Checks, "repeated-sample") || !strings.HasPrefix(result.Contract, scriptInterface03+"#") {
				t.Fatalf("wrong 0.3 role evidence: %+v", result)
			}
		})
	}
}

func TestScriptComponent03RejectsMismatchedDeclaration(t *testing.T) {
	metadata := strings.Replace(templateMetadata03, scriptInterface03, scriptInterface, 1)
	_, err := Validate(t.Context(), packagedFixture(t, "component-template-script-0.3.0", metadata))
	if err == nil || errors.Is(err, ErrUnsupportedContract) {
		t.Fatalf("expected a supported contract with a mismatched runtime declaration to fail, got %v", err)
	}
}

const scriptMetadata03 = `{"metadata_version":1,"transport":"wasm-component","id":"script-engine-0.3.0-fixture","name":"Script engine 0.3.0 fixture","description":"Registry script fixture","license":"MIT","repository":"https://github.com/example/plugin","plugin_version":"1.0.0","interface":"kjanat:actionlint/script-engine@0.3.0","wit_sha256":"6c289637bd345bd66db965fe9084fb8e5a4f03b0d5655497025e2d1a05c36479","engine":{"name":"json1","version":"1.0.0"},"capabilities":{"script_shells":["bash"],"fixes":true,"reported_sources":true,"resources":["directory"]},"config_schema":{"type":"object"},"rules":[{"name":"json1","description":"Decode ShellCheck json1 output","category":"correctness","subcategory":"shell","maturity":"stable","provider":"script-engine-0.3.0-fixture","recommended":true,"documentation_url":"https://example.com/json1","options_schema":{"type":"object"}}]}`
const templateMetadata03 = `{"metadata_version":1,"transport":"wasm-component","id":"template-script-engine-0.3.0-fixture","name":"Template script engine 0.3.0 fixture","description":"Registry template fixture","license":"MIT","repository":"https://github.com/example/plugin","plugin_version":"1.0.0","interface":"kjanat:actionlint/script-engine@0.3.0","wit_sha256":"6c289637bd345bd66db965fe9084fb8e5a4f03b0d5655497025e2d1a05c36479","template_contract":"kjanat:actionlint/template-effects@0.1.0","engine":{"name":"template","version":"1.0.0"},"capabilities":{"script_shells":["bash"],"fixes":true,"reported_sources":true,"resources":["directory"]},"config_schema":{"type":"object"},"rules":[{"name":"template","description":"Report the first character of a snippet","category":"correctness","subcategory":"shell","maturity":"stable","provider":"template-script-engine-0.3.0-fixture","recommended":true,"documentation_url":"https://example.com/template","options_schema":{"type":"object"}}]}`
