package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"registry.actionlint.kjanat.dev/internal/compatibility"
	"runtime"
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
	runnerAsOf, args := time.Now().UTC().Format(time.DateOnly), os.Args[1:]
	if os.Getenv(panickingCheckerVariable) == "1" {
		panic("checker crashed")
	}
	if len(args) == 1 && args[0] == compatibility.ProtocolProbe {
		fmt.Println(compatibility.ProtocolVersion)
		os.Exit(0)
	}
	if len(args) == 3 && args[0] == "--runner-as-of" {
		runnerAsOf, args = args[1], args[2:]
	}
	if len(args) == 1 && filepath.Base(args[0]) == "plugin.wasm" {
		data, err := os.ReadFile(args[0])
		if err != nil || os.Getenv("GH_TOKEN") != "" || bytes.Equal(data, []byte("crash")) {
			os.Exit(7)
		}
		if bytes.HasPrefix(data, []byte("\x00asm\x0d\x00\x01\x00")) {
			sum := sha256.Sum256(data)
			exports := []string{"kjanat:actionlint/analyzer@0.2.0"}
			if bytes.Contains(data, []byte(otherPlatformLayer)) {
				exports = []string{"kjanat:actionlint/runner-provider@0.3.0"}
			}
			reply := compatibility.Report{SchemaVersion: compatibility.ProtocolVersion, ArtifactSHA256: hex.EncodeToString(sum[:]), Host: compatibility.Host{Name: "fixture", Revision: "host-a"}, Policy: "test/1", Outcome: "passed", Checks: []string{"sample"}, RunnerAsOf: runnerAsOf, Imports: []string{"wasi:cli/environment@0.2.0"}, Exports: exports}
			if err = json.NewEncoder(os.Stdout).Encode(reply); err != nil {
				os.Exit(8)
			}
			os.Exit(0)
		}
		outcome := string(data)
		if outcome == "ignores-date" {
			outcome, runnerAsOf = "passed", foreignDateFixture
		}
		sum := sha256.Sum256(data)
		reply := compatibility.Report{SchemaVersion: compatibility.ProtocolVersion, ArtifactSHA256: hex.EncodeToString(sum[:]), Host: compatibility.Host{Name: "fixture", Revision: "host-a"}, Policy: "test/1", Outcome: outcome, Checks: []string{"sample"}, RunnerAsOf: runnerAsOf}
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
			result, err := checkLocal(t.Context(), executable, path, entry, "")
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
	if _, err = checkLocal(t.Context(), executable, path, entry, ""); err == nil {
		t.Fatal("tampered artifact reached checker")
	}
	if _, err = checkLocal(t.Context(), filepath.Join(t.TempDir(), "missing"), path, entry, ""); err == nil {
		t.Fatal("missing checker became evidence")
	}
}

const foreignDateFixture = "2001-01-01"

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
	evidence.Report.SchemaVersion, evidence.Report.RunnerAsOf, evidence.ObservedAt = 2, runnerAsOf, observedAt
	return evidence
}

// dayOfCheck reports whether date is the UTC day at start or now, so a check
// that runs across midnight still matches.
func dayOfCheck(start time.Time, date string) bool {
	return date == start.UTC().Format(time.DateOnly) || date == time.Now().UTC().Format(time.DateOnly)
}

func TestRecheckRecordsTodayWithoutStoredDate(t *testing.T) {
	entry := acceptedFixture(t)
	for name, stored := range map[string][]compatibility.Evidence{"no evidence": nil, "undated evidence": {observation(entry, "passed")}} {
		t.Run(name, func(t *testing.T) {
			store, index, entry, executable, path := recheckFixture(t, "passed", stored...)
			start := time.Now()
			evidence, err := recheckLocal(t.Context(), store, index, executable, path, entry)
			if err != nil {
				t.Fatal(err)
			}
			if !dayOfCheck(start, evidence.Report.RunnerAsOf) {
				t.Fatalf("recheck did not use the current date: %+v", evidence.Report)
			}
			recorded, err := store.Load(index)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.ContainsFunc(recorded, func(e compatibility.Evidence) bool { return e.Report.RunnerAsOf == evidence.Report.RunnerAsOf }) {
				t.Fatalf("recheck did not record its date: %+v", recorded)
			}
		})
	}
}

// The earliest observation carries the later date, so choosing the smallest
// date instead of the earliest observation fails.
func TestRecheckReplaysDateOfEarliestObservation(t *testing.T) {
	entry := acceptedFixture(t)
	first := time.Now().UTC().Add(-72 * time.Hour)
	store, index, entry, executable, path := recheckFixture(t, "passed",
		datedObservation(entry, "2026-12-08", first.Add(48*time.Hour)),
		datedObservation(entry, "2026-12-10", first),
		observation(entry, "passed"))
	evidence, err := recheckLocal(t.Context(), store, index, executable, path, entry)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Report.RunnerAsOf != "2026-12-10" {
		t.Fatalf("recheck did not replay the earliest observation's date: %+v", evidence.Report)
	}
}

func TestRecheckRejectsCheckerIgnoringStoredDate(t *testing.T) {
	entry := acceptedFixture(t)
	store, index, entry, executable, path := recheckFixture(t, "ignores-date", datedObservation(entry, "2026-12-08", time.Now().UTC()))
	before, err := store.Load(index)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = recheckLocal(t.Context(), store, index, executable, path, entry); err == nil || !strings.Contains(err.Error(), "instead of") {
		t.Fatalf("checker that ignored the stored date was accepted: %v", err)
	}
	after, err := store.Load(index)
	if err != nil || len(after) != len(before) {
		t.Fatalf("rejected recheck stored evidence: %d -> %d, %v", len(before), len(after), err)
	}
}

func TestCheckRejectsDateOtherThanRegistryDate(t *testing.T) {
	_, _, entry, executable, path := recheckFixture(t, "ignores-date")
	if _, err := checkLocal(t.Context(), executable, path, entry, ""); err == nil || !strings.Contains(err.Error(), "\""+foreignDateFixture+"\" instead of") {
		t.Fatalf("report dated %s was accepted without a requested date: %v", foreignDateFixture, err)
	}
}

func TestCheckPassesTodayToProtocol2Checker(t *testing.T) {
	_, _, entry, _, path := recheckFixture(t, "passed")
	report := fmt.Sprintf(`{"schema_version":2,"artifact_sha256":%q,"host":{"name":"actionlint","revision":"v2"},"policy":"actionlint-smoke/1","outcome":"passed","checks":["metadata-v1"],"runner_as_of":"%%s"}`, entry.Submission.SHA256)
	checker, argsLog := shellChecker(t, 2, report)
	start := time.Now()
	evidence, err := checkLocal(t.Context(), checker, path, entry, "")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(argsLog)
	if err != nil {
		t.Fatal(err)
	}
	calls := strings.Split(strings.TrimSpace(string(data)), "\n")
	fields := strings.Fields(calls[len(calls)-1])
	if len(calls) != 2 || calls[0] != compatibility.ProtocolProbe || len(fields) != 3 || fields[0] != "--runner-as-of" || !dayOfCheck(start, fields[1]) || evidence.Report.RunnerAsOf != fields[1] {
		t.Fatalf("protocol 2 checker did not receive the registry's date: %q, %+v", calls, evidence.Report)
	}
}

// shellChecker writes a POSIX shell checker that logs its arguments. A protocol
// 1 checker accepts exactly one existing artifact path, like the original
// checker, and prints report. Protocol 2 and later answer the probe, accept
// --runner-as-of, and print report as a printf format with the date as its
// only argument.
func shellChecker(t *testing.T, protocol int, report string) (string, string) {
	t.Helper()
	directory := t.TempDir()
	argsLog := filepath.Join(directory, "args.log")
	script := "printf '%s\\n' \"$*\" >> '" + argsLog + "'\n"
	if protocol > 1 {
		script += fmt.Sprintf("if [ \"$1\" = %s ]; then printf '%%s\\n' %d; exit 0; fi\n", compatibility.ProtocolProbe, protocol)
		script += "if [ \"$1\" = --runner-as-of ]; then date=$2; shift 2; fi\n"
		script += "[ \"$#\" -eq 1 ] && [ -f \"$1\" ] || exit 1\nprintf '" + report + "\\n' \"$date\"\n"
	} else {
		script += "[ \"$#\" -eq 1 ] && [ -f \"$1\" ] || exit 1\nprintf '%s\\n' '" + report + "'\n"
	}
	return writeShellChecker(t, directory, script), argsLog
}

func writeShellChecker(t *testing.T, directory, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake checker is a POSIX shell script")
	}
	path := filepath.Join(directory, "checker")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRecheckGivesProtocol1CheckerNoDate(t *testing.T) {
	entry := acceptedFixture(t)
	store, index, entry, _, path := recheckFixture(t, "passed", datedObservation(entry, "2026-12-08", time.Now().UTC()))
	report := fmt.Sprintf(`{"schema_version":1,"artifact_sha256":%q,"host":{"name":"actionlint","revision":"v1"},"policy":"actionlint-smoke/1","outcome":"passed","checks":["metadata-v1"]}`, entry.Submission.SHA256)
	checker, argsLog := shellChecker(t, 1, report)
	evidence, err := recheckLocal(t.Context(), store, index, checker, path, entry)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Report.SchemaVersion != 1 || evidence.Report.RunnerAsOf != "" {
		t.Fatalf("protocol 1 record is not undated: %+v", evidence.Report)
	}
	data, err := os.ReadFile(argsLog)
	if err != nil {
		t.Fatal(err)
	}
	calls := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(calls) != 2 || calls[0] != compatibility.ProtocolProbe || strings.Contains(calls[1], "--runner-as-of") {
		t.Fatalf("protocol 1 checker received %q", calls)
	}
}

func TestCheckRejectsUnknownCheckerProtocol(t *testing.T) {
	_, _, entry, _, path := recheckFixture(t, "passed")
	checker, _ := shellChecker(t, 4, "{}")
	if _, err := checkLocal(t.Context(), checker, path, entry, ""); err == nil || !strings.Contains(err.Error(), "unsupported checker protocol") {
		t.Fatalf("protocol 4 checker was called: %v", err)
	}
}

func TestCheckRejectsAbnormalProtocolProbe(t *testing.T) {
	timeout := checkerProbeTimeout
	t.Cleanup(func() { checkerProbeTimeout = timeout })
	checkerProbeTimeout = 200 * time.Millisecond
	_, _, entry, _, path := recheckFixture(t, "passed")
	for name, body := range map[string]string{
		"timeout": "while :; do :; done\n",
		"signal":  "kill -KILL $$\n",
	} {
		t.Run(name, func(t *testing.T) {
			checker := writeShellChecker(t, t.TempDir(), body)
			if _, err := checkLocal(t.Context(), checker, path, entry, ""); err == nil || !strings.Contains(err.Error(), "checker protocol probe") {
				t.Fatalf("abnormal probe was not reported as a probe failure: %v", err)
			}
		})
	}
}

const panickingCheckerVariable = "REGISTRY_TEST_PANICKING_CHECKER"

// A Go panic exits with status 2 and prints nothing to stdout; only status 1
// identifies a protocol 1 checker.
func TestCheckRejectsPanickingProtocolProbe(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	_, _, entry, _, path := recheckFixture(t, "passed")
	checker := writeShellChecker(t, t.TempDir(), panickingCheckerVariable+"=1 exec '"+executable+"' \"$@\"\n")
	if _, err := checkLocal(t.Context(), checker, path, entry, ""); err == nil || !strings.Contains(err.Error(), "checker protocol probe failed: exit status 2") {
		t.Fatalf("panicking probe was not reported as a probe failure: %v", err)
	}
}

func checkLocal(ctx context.Context, executable, path string, entry Entry, runnerAsOf string) (compatibility.Evidence, error) {
	observed, err := CheckCompatibility(ctx, executable, path, entry, runnerAsOf, nil)
	if err != nil {
		return compatibility.Evidence{}, err
	}
	if len(observed) != 1 {
		return compatibility.Evidence{}, fmt.Errorf("a release asset check returned %d observations", len(observed))
	}
	return observed[0], nil
}

func recheckLocal(ctx context.Context, store EvidenceStore, index Index, executable, path string, entry Entry) (compatibility.Evidence, error) {
	observed, err := store.Recheck(ctx, index, executable, path, entry, nil)
	if err != nil {
		return compatibility.Evidence{}, err
	}
	if len(observed) != 1 {
		return compatibility.Evidence{}, fmt.Errorf("a release asset recheck returned %d observations", len(observed))
	}
	return observed[0], nil
}

func TestCheckKeepsProtocol3Interfaces(t *testing.T) {
	_, _, entry, _, path := recheckFixture(t, "passed")
	imports, exports := []string{"wasi:cli/environment@0.2.0"}, []string{"kjanat:actionlint/analyzer@0.2.0"}
	report := func(version int) string {
		return fmt.Sprintf(`{"schema_version":%d,"artifact_sha256":%q,"host":{"name":"actionlint","revision":"v3"},"policy":"actionlint-smoke/1","outcome":"passed","checks":["metadata-v1"],"runner_as_of":"%%s","imports":[%q],"exports":[%q]}`, version, entry.Submission.SHA256, imports[0], exports[0])
	}
	checker, _ := shellChecker(t, 3, report(3))
	evidence, err := checkLocal(t.Context(), checker, path, entry, "2026-12-08")
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Report.SchemaVersion != 3 || !slices.Equal(evidence.Report.Imports, imports) || !slices.Equal(evidence.Report.Exports, exports) {
		t.Fatalf("protocol 3 evidence lost its interfaces: %+v", evidence.Report)
	}
	checker, _ = shellChecker(t, 2, report(2))
	if _, err := checkLocal(t.Context(), checker, path, entry, "2026-12-08"); err == nil {
		t.Fatal("protocol 2 report with interfaces became evidence")
	}
}
