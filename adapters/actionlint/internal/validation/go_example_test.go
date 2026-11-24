package validation

import (
	"slices"
	"testing"
)

func TestPackagedGoExample(t *testing.T) {
	result, err := Validate(t.Context(), hostFixture(t, "component-insecure-download"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Kind != "component" || !slices.Contains(result.Rules, "insecure-download") || !slices.Contains(result.Checks, "repeated-sample") {
		t.Fatalf("unexpected validation result: %+v", result)
	}
}
