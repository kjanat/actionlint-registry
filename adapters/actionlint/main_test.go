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

func captureRun(t *testing.T, args ...string) []byte {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = writer
	runErr := run(t.Context(), args)
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
	return output
}

func TestRunReportsRunnerAssessmentDate(t *testing.T) {
	if err := run(t.Context(), []string{"--runner-as-of", "2026-02-30", "main.go"}); err == nil || !strings.Contains(err.Error(), "--runner-as-of") {
		t.Fatalf("accepted an invalid assessment date: %v", err)
	}
	output := captureRun(t, "--runner-as-of", "2026-12-08", "main.go")
	var reply report
	if err := json.Unmarshal(output, &reply); err != nil {
		t.Fatal(err)
	}
	if reply.SchemaVersion != 2 || reply.RunnerAsOf != "2026-12-08" {
		t.Fatalf("report lost the protocol version or the requested assessment date: %s", output)
	}
}

func TestRunAnswersProtocolProbe(t *testing.T) {
	if output := string(captureRun(t, "--protocol")); output != "2\n" {
		t.Fatalf("protocol probe answered %q", output)
	}
	for _, args := range [][]string{{"--protocol", "main.go"}, {"--protocol", "--runner-as-of", "2026-12-08"}} {
		if err := run(t.Context(), args); err == nil {
			t.Fatalf("protocol probe accepted extra arguments %q", args)
		}
	}
}
