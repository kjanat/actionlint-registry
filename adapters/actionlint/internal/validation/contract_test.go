package validation

import (
	"errors"
	"strings"
	"testing"
)

const componentContractDigest = "287f569cb6587a23f2195f9d8398f370c32a2b21deed1fac42f3b56fd03c7c23"
const scriptContractDigest = "c20d7e9e516166576fdf19bfd86e0843838179b12ad55350c33db8d04c2eaa9b"
const runnerContractDigest = "2a995ebe267d4d5df5664c0f6f48b40cc770116ef9375935f26f3a648652df9f"

// ShellCheck vendors the same analyzer types with older documentation comments.
// Both source digests must reach type validation, including incompatible exports.
func TestAnalyzerCompatibilityUsesExportedTypes(t *testing.T) {
	for _, digest := range []string{componentContractDigest, "a0096f562ab3da46b30d0f025ad1c6ed0d46e5b7ea1a53660b3214e3270fcbee"} {
		metadata := strings.Replace(componentMetadata, componentContractDigest, digest, 1)
		result, err := Validate(t.Context(), packagedFixture(t, "component-no-sudo", metadata))
		if err != nil {
			t.Fatal(err)
		}
		if result.Contract != componentInterface+"#sha256="+digest {
			t.Fatalf("changed declared source identity: %s", result.Contract)
		}
		_, err = Validate(t.Context(), packagedFixture(t, "component-wrong-record", metadata))
		if err == nil || errors.Is(err, ErrUnsupportedContract) {
			t.Fatalf("wrong types must fail runtime validation: %v", err)
		}
	}
	for _, invalid := range []string{"", "invalid", strings.Repeat("A", 64), strings.Repeat("0", 63)} {
		metadata := strings.Replace(componentMetadata, componentContractDigest, invalid, 1)
		if _, err := Validate(t.Context(), packagedFixture(t, "component-no-sudo", metadata)); err == nil {
			t.Fatal("accepted malformed digest")
		}
	}
}

func TestComponentInterfaceVersions(t *testing.T) {
	for _, role := range []string{"analyzer", "script-engine", "runner-provider"} {
		current := "kjanat:actionlint/" + role + "@0.2.0"
		if !supportedComponent(current) {
			t.Fatalf("current interface %q is unsupported", current)
		}
		old := "kjanat:actionlint/" + role + "@0.1.0"
		if supportedComponent(old) {
			t.Fatalf("old interface %q is supported", old)
		}
	}
}
