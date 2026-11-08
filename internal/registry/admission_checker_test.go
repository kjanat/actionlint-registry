package registry

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/go-github/v93/github"
	"registry.actionlint.kjanat.dev/internal/artifact"
)

func fakeChecker(t *testing.T, digest, outcome, checks, detail string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake checker is a POSIX shell script")
	}
	path := filepath.Join(t.TempDir(), "checker")
	report := fmt.Sprintf(`{"schema_version":1,"artifact_sha256":%q,"host":{"name":"actionlint","revision":"afaa8f8a5c53"},"policy":"actionlint-smoke/1","outcome":%q,"checks":%s%s}`, digest, outcome, checks, detail)
	if err := os.WriteFile(path, []byte("#!/bin/sh\nprintf '%s\\n' '"+report+"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAdmissionRejectsFailedCompatibility(t *testing.T) {
	digest := sampleReceipt().Submission.Digest()
	for name, test := range map[string]struct {
		checker string
		admit   bool
	}{
		"passed":      {fakeChecker(t, digest, "passed", `["metadata-v1"]`, ""), true},
		"unsupported": {fakeChecker(t, digest, "unsupported", `[]`, `,"detail":"unknown contract"`), true},
		"failed":      {fakeChecker(t, digest, "failed", `[]`, `,"detail":"config_schema differs from runtime"`), false},
	} {
		t.Run(name, func(t *testing.T) {
			service := Service{
				Providers: map[string]ReleaseProvider{"github": fixtureGitHub(t, func(*github.RepositoryRelease) {})},
				Inspect: func(context.Context, string) (artifact.Declaration, error) {
					return sampleDeclaration(), nil
				},
				Checker: test.checker,
			}
			index := EmptyIndex()
			_, err := service.Admit(t.Context(), &index, sampleReceipt())
			if test.admit {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || FailureDisposition(err) != "rejected" || len(index.Entries) != 0 {
				t.Fatalf("failed compatibility admitted or retried: %v", err)
			}
		})
	}
}
