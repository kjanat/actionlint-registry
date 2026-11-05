package validation

import (
	"slices"
	"strings"
	"testing"
)

const scriptMetadata = `{"metadata_version":1,"transport":"wasm-component","id":"echo-component","name":"Echo component","description":"Registry script fixture","license":"MIT","repository":"https://github.com/example/plugin","plugin_version":"1.0.0","interface":"kjanat:actionlint/script-engine@0.2.0","contract_sha256":"c20d7e9e516166576fdf19bfd86e0843838179b12ad55350c33db8d04c2eaa9b","engine":{"name":"echo","version":"1.0.0"},"capabilities":{"script_shells":["python"]},"config_schema":{"type":"object"},"rules":[{"name":"echo","description":"Find a missing value","category":"correctness","subcategory":"python","maturity":"stable","provider":"echo-component","recommended":true,"documentation_url":"https://example.com/echo","options_schema":{"type":"object"},"fix_availability":"none"}]}`
const runnerMetadata = `{"metadata_version":1,"transport":"wasm-component","id":"buildkite-runners","name":"Buildkite runners","description":"Registry runner fixture","license":"MIT","repository":"https://github.com/example/plugin","plugin_version":"1.0.0","interface":"kjanat:actionlint/runner-provider@0.2.0","contract_sha256":"2a995ebe267d4d5df5664c0f6f48b40cc770116ef9375935f26f3a648652df9f"}`

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
			for _, metadata := range []string{
				strings.Replace(test.metadata, test.id, "different-plugin", 1),
				strings.Replace(test.metadata, `"plugin_version":"1.0.0"`, `"plugin_version":"2.0.0"`, 1),
			} {
				if _, err := Validate(t.Context(), packagedFixture(t, test.fixture, metadata)); err == nil {
					t.Fatal("accepted static/runtime identity mismatch")
				}
			}
			if _, err := Validate(t.Context(), packagedFixture(t, "component-no-sudo", test.metadata)); err == nil {
				t.Fatal("accepted a component without its declared role")
			}
		})
	}
}
