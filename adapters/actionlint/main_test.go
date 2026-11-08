package main

import (
	"strings"
	"testing"

	"actionlint.kjanat.dev/v2/registry/validation/internal/validation"
)

func TestRunRequiresHostRevision(t *testing.T) {
	revision := validation.HostCommit
	t.Cleanup(func() { validation.HostCommit = revision })
	validation.HostCommit = ""
	if err := run(t.Context(), []string{"main.go"}); err == nil || !strings.Contains(err.Error(), "host module revision") {
		t.Fatalf("reported without a host revision: %v", err)
	}
}
