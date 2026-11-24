package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-github/v93/github"
	"registry.actionlint.kjanat.dev/internal/artifact"
)

func fakeChecker(t *testing.T, digest, outcome, checks, detail string) string {
	t.Helper()
	report := fmt.Sprintf(`{"schema_version":1,"artifact_sha256":%q,"host":{"name":"actionlint","revision":"afaa8f8a5c53"},"policy":"actionlint-smoke/1","outcome":%q,"checks":%s%s}`, digest, outcome, checks, detail)
	checker, _ := shellChecker(t, 1, report)
	return checker
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
			admission, err := service.Admit(t.Context(), &index, sampleReceipt())
			if test.admit {
				if err != nil {
					t.Fatal(err)
				}
				if admission.Evidence == nil || admission.Evidence.Report.Outcome != name || admission.Evidence.Report.ArtifactSHA256 != digest {
					t.Fatalf("admission dropped its compatibility evidence: %+v", admission.Evidence)
				}
				return
			}
			if err == nil || FailureDisposition(err) != "rejected" || len(index.Entries) != 0 {
				t.Fatalf("failed compatibility admitted or retried: %v", err)
			}
		})
	}
}

func TestCheckerReportKeepsRunnerAssessmentDate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plugin.wasm")
	if err := os.WriteFile(path, []byte("candidate"), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("candidate"))
	digest := hex.EncodeToString(sum[:])
	report := fmt.Sprintf(`{"schema_version":2,"artifact_sha256":%q,"host":{"name":"actionlint","revision":"v2"},"policy":"actionlint-smoke/1","outcome":"passed","checks":["host-resolution"],"runner_as_of":"%%s"}`, digest)
	checker, _ := shellChecker(t, 2, report)
	evidence, err := CheckArtifact(t.Context(), checker, path, digest, "2026-12-08")
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Report.SchemaVersion != 2 || evidence.Report.RunnerAsOf != "2026-12-08" {
		t.Fatalf("checker report lost its protocol or runner assessment date: %+v", evidence.Report)
	}
}
