package main

import (
	"encoding/json"
	"io"
	"os"
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

func TestRunReportsRunnerAssessmentDate(t *testing.T) {
	if err := run(t.Context(), []string{"--runner-as-of", "2026-02-30", "main.go"}); err == nil || !strings.Contains(err.Error(), "--runner-as-of") {
		t.Fatalf("accepted an invalid assessment date: %v", err)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = writer
	runErr := run(t.Context(), []string{"--runner-as-of", "2026-12-08", "main.go"})
	os.Stdout = stdout
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if runErr != nil {
		t.Fatal(runErr)
	}
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	var reply report
	if err := json.Unmarshal(output, &reply); err != nil {
		t.Fatal(err)
	}
	if reply.RunnerAsOf != "2026-12-08" {
		t.Fatalf("report lost the requested assessment date: %s", output)
	}
}
