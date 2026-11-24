package registry

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"registry.actionlint.kjanat.dev/internal/compatibility"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestCapturedOutputCannotBypassLimit(t *testing.T) {
	buffer := &boundedBuffer{limit: 8}
	reader := struct{ io.Reader }{strings.NewReader(strings.Repeat("x", 32))}
	if _, err := io.Copy(buffer, reader); err == nil {
		t.Fatal("io.Copy bypassed output budget")
	}
	if len(buffer.Bytes()) > 8 {
		t.Fatal("buffer retained data beyond budget")
	}
}

// The test executable acts as a checker when launched on the parent's snapshot.
func TestMain(m *testing.M) {
	runnerAsOf, args := checkerTodayFixture, os.Args[1:]
	if len(args) == 3 && args[0] == "--runner-as-of" {
		runnerAsOf, args = args[1], args[2:]
	}
	if len(args) == 1 && filepath.Base(args[0]) == "plugin.wasm" {
		data, err := os.ReadFile(args[0])
		if err != nil || os.Getenv("GH_TOKEN") != "" || bytes.Equal(data, []byte("crash")) {
			os.Exit(7)
		}
		outcome := string(data)
		if outcome == "ignores-date" {
			outcome, runnerAsOf = "passed", checkerTodayFixture
		}
		sum := sha256.Sum256(data)
		reply := compatibility.Report{SchemaVersion: 1, ArtifactSHA256: hex.EncodeToString(sum[:]), Host: compatibility.Host{Name: "fixture", Revision: "host-a"}, Policy: "test/1", Outcome: outcome, Checks: []string{"sample"}, RunnerAsOf: runnerAsOf}
		if reply.Outcome != "passed" {
			reply.Detail = "unsupported or failed fixture"
		}
		if bytes.Equal(data, []byte("wrong-digest")) {
			reply.Outcome = "failed"
			reply.ArtifactSHA256 = strings.Repeat("0", 64)
		}
		if err = json.NewEncoder(os.Stdout).Encode(reply); err != nil {
			os.Exit(8)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}
func TestCheckerFailuresNeverMutateAdmission(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GH_TOKEN", "must-not-reach-checker")
	for _, outcome := range []string{"passed", "failed", "unsupported", "crash", "wrong-digest"} {
		t.Run(outcome, func(t *testing.T) {
			entry := acceptedFixture(t)
			raw := []byte(outcome)
			sum := sha256.Sum256(raw)
			entry.Submission.SHA256 = hex.EncodeToString(sum[:])
			before, err := json.Marshal(entry)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "source.wasm")
			if err = os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			result, err := CheckCompatibility(t.Context(), executable, path, entry, "")
			if outcome == "crash" || outcome == "wrong-digest" {
				if err == nil {
					t.Fatal("invalid checker response became evidence")
				}
			} else if err != nil || result.Report.Outcome != outcome || result.CheckerSHA256 == "" {
				t.Fatalf("report: %+v, %v", result, err)
			}
			after, err := json.Marshal(entry)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("checker mutated admission record")
			}
		})
	}
	entry := acceptedFixture(t)
	path := filepath.Join(t.TempDir(), "tampered.wasm")
	if err = os.WriteFile(path, []byte("passed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = CheckCompatibility(t.Context(), executable, path, entry, ""); err == nil {
		t.Fatal("tampered artifact reached checker")
	}
	if _, err = CheckCompatibility(t.Context(), filepath.Join(t.TempDir(), "missing"), path, entry, ""); err == nil {
		t.Fatal("missing checker became evidence")
	}
}

const checkerTodayFixture = "2026-11-24"

func recheckFixture(t *testing.T, content string, stored ...compatibility.Evidence) (EvidenceStore, Index, Entry, string, string) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	entry := acceptedFixture(t)
	sum := sha256.Sum256([]byte(content))
	entry.Submission.SHA256 = hex.EncodeToString(sum[:])
	entry.Receipt.Submission = entry.Submission
	declaration := *entry.Artifact
	declaration.SHA256 = entry.Submission.SHA256
	entry.Artifact = &declaration
	index := EmptyIndex()
	if err = index.Add(entry); err != nil {
		t.Fatal(err)
	}
	store := EvidenceStore{Directory: filepath.Join(t.TempDir(), "compatibility")}
	for _, evidence := range stored {
		evidence.Report.ArtifactSHA256 = entry.Submission.SHA256
		if err = store.Add(index, evidence); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), "source.wasm")
	if err = os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return store, index, entry, executable, path
}

func datedObservation(entry Entry, runnerAsOf string, observedAt time.Time) compatibility.Evidence {
	evidence := observation(entry, "passed")
	evidence.Report.RunnerAsOf, evidence.ObservedAt = runnerAsOf, observedAt
	return evidence
}

func TestRecheckRecordsTodayWithoutStoredDate(t *testing.T) {
	entry := acceptedFixture(t)
	for name, stored := range map[string][]compatibility.Evidence{"no evidence": nil, "undated evidence": {observation(entry, "passed")}} {
		t.Run(name, func(t *testing.T) {
			store, index, entry, executable, path := recheckFixture(t, "passed", stored...)
			evidence, err := store.Recheck(t.Context(), index, executable, path, entry)
			if err != nil {
				t.Fatal(err)
			}
			if evidence.Report.RunnerAsOf != checkerTodayFixture {
				t.Fatalf("recheck did not use the checker's current date: %+v", evidence.Report)
			}
			recorded, err := store.Load(index)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.ContainsFunc(recorded, func(e compatibility.Evidence) bool { return e.Report.RunnerAsOf == checkerTodayFixture }) {
				t.Fatalf("recheck did not record its date: %+v", recorded)
			}
		})
	}
}

func TestRecheckReplaysEarliestStoredDate(t *testing.T) {
	entry := acceptedFixture(t)
	first := time.Now().UTC().Add(-72 * time.Hour)
	store, index, entry, executable, path := recheckFixture(t, "passed",
		datedObservation(entry, "2026-12-10", first.Add(48*time.Hour)),
		datedObservation(entry, "2026-12-08", first),
		observation(entry, "passed"))
	evidence, err := store.Recheck(t.Context(), index, executable, path, entry)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Report.RunnerAsOf != "2026-12-08" {
		t.Fatalf("recheck did not replay the stored date: %+v", evidence.Report)
	}
}

func TestRecheckRejectsCheckerIgnoringStoredDate(t *testing.T) {
	entry := acceptedFixture(t)
	store, index, entry, executable, path := recheckFixture(t, "ignores-date", datedObservation(entry, "2026-12-08", time.Now().UTC()))
	before, err := store.Load(index)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Recheck(t.Context(), index, executable, path, entry); err == nil || !strings.Contains(err.Error(), "instead of") {
		t.Fatalf("checker that ignored the stored date was accepted: %v", err)
	}
	after, err := store.Load(index)
	if err != nil || len(after) != len(before) {
		t.Fatalf("rejected recheck stored evidence: %d -> %d, %v", len(before), len(after), err)
	}
}
