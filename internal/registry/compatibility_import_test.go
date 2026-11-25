package registry

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"registry.actionlint.kjanat.dev/internal/compatibility"
)

func importPlan(entries ...Entry) CompatibilityPlan {
	plan := CompatibilityPlan{SchemaVersion: 1, CheckerSHA256: strings.Repeat("a", 64), HostRevision: "3747a77b7ff9"}
	for _, entry := range entries {
		plan.Targets = append(plan.Targets, CompatibilityTarget{Plugin: entry.Name(), Version: entry.Submission.Tag, SHA256: entry.Submission.Digest()})
	}
	return plan
}

func importObservation(entry Entry, outcome string) compatibility.Evidence {
	plan := importPlan(entry)
	e := observation(entry, outcome)
	e.Report.SchemaVersion = compatibility.ProtocolVersion
	e.Report.Host = compatibility.Host{Name: "actionlint", Revision: plan.HostRevision}
	e.Report.Policy = "actionlint-smoke/1"
	e.Report.RunnerAsOf = e.ObservedAt.Format(time.DateOnly)
	e.CheckerSHA256 = plan.CheckerSHA256
	return e
}

func TestImportKeepsCompletedChecksWhenAnotherArtifactIsUnavailable(t *testing.T) {
	entry := acceptedFixture(t)
	unavailable := changedArtifactFixture(t, entry, "v2.0.0", "core", "example.wasm")
	index := Index{Entries: []Entry{entry, unavailable}}
	plan := importPlan(entry, unavailable)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, unavailable.Submission.Digest()+".unavailable"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, outcome := range []string{"passed", "failed", "unsupported"} {
		t.Run(outcome, func(t *testing.T) {
			store := EvidenceStore{Directory: t.TempDir()}
			e := importObservation(entry, outcome)
			e.ObservedAt = time.Now().UTC().Truncate(24 * time.Hour).Add(-time.Second)
			e.Report.RunnerAsOf = e.ObservedAt.Format(time.DateOnly)
			path := filepath.Join(dir, entry.Submission.Digest()+".json")
			for i := range 2 {
				if i > 0 {
					// A second run planned the same check before the first published.
					e.ObservedAt = e.ObservedAt.Add(2 * time.Second)
					e.Report.RunnerAsOf = e.ObservedAt.Format(time.DateOnly)
				}
				if err := WriteJSON(path, []compatibility.Evidence{e}); err != nil {
					t.Fatal(err)
				}
				if err := store.ImportCompatibility(index, plan, dir, plan.CheckerSHA256, plan.HostRevision); err != nil {
					t.Fatal(err)
				}
			}
			results, err := store.Load(index)
			if err != nil || len(results) != 1 || results[0].Release() != entry.Submission.Digest() || results[0].Report.Outcome != outcome || !results[0].ObservedAt.Before(e.ObservedAt) {
				t.Fatalf("stored observations: %v, %v", results, err)
			}
			e.Report.Checks = []string{""}
			if err := WriteJSON(path, []compatibility.Evidence{e}); err != nil {
				t.Fatal(err)
			}
			if err := store.ImportCompatibility(index, plan, dir, plan.CheckerSHA256, plan.HostRevision); err == nil {
				t.Fatal("skipped validation of an invalid duplicate")
			}
		})
	}
}

func TestImportRejectsFilesOutsideThePlan(t *testing.T) {
	entry := acceptedFixture(t)
	index := Index{Entries: []Entry{entry}}
	plan := importPlan(entry)
	name := entry.Submission.Digest() + ".json"
	valid, err := json.Marshal([]compatibility.Evidence{importObservation(entry, "passed")})
	if err != nil {
		t.Fatal(err)
	}
	for mode, files := range map[string]map[string][]byte{
		"missing":                     {},
		"extra":                       {name: valid, "other": nil},
		"wrong name":                  {"notes.json": valid},
		"nonempty unavailable marker": {entry.Submission.Digest() + ".unavailable": []byte("skip")},
		"unknown field":               {name: bytes.Replace(valid, []byte(`[{`), []byte(`[{"unknown":true,`), 1)},
		"extra JSON":                  {name: append(slices.Clone(valid), "[]"...)},
		"oversized file":              {name: make([]byte, maxRecordBytes+1)},
		"symlink":                     {},
	} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			for file, data := range files {
				if err := os.WriteFile(filepath.Join(dir, file), data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "symlink" {
				target := filepath.Join(t.TempDir(), name)
				if err := os.WriteFile(target, valid, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
					t.Fatal(err)
				}
			}
			store := EvidenceStore{Directory: t.TempDir()}
			if err := store.ImportCompatibility(index, plan, dir, plan.CheckerSHA256, plan.HostRevision); err == nil {
				t.Fatalf("import accepted %s", mode)
			}
		})
	}
}

func TestInvalidReportRollsBackEarlierTargets(t *testing.T) {
	entry := acceptedFixture(t)
	next := changedArtifactFixture(t, entry, "v2.0.0", "core", "plugin.wasm")
	index := Index{Entries: []Entry{entry, next}}
	plan := importPlan(entry, next)
	for _, field := range []string{"release", "checker", "host name", "host revision", "policy", "protocol"} {
		t.Run(field, func(t *testing.T) {
			dir := t.TempDir()
			store := EvidenceStore{Directory: t.TempDir()}
			if err := WriteJSON(filepath.Join(dir, entry.Submission.Digest()+".json"), []compatibility.Evidence{importObservation(entry, "passed")}); err != nil {
				t.Fatal(err)
			}
			e := importObservation(next, "failed")
			switch field {
			case "release":
				e.Report.ArtifactSHA256 = entry.Submission.Digest()
			case "checker":
				e.CheckerSHA256 = strings.Repeat("f", 64)
			case "host name":
				e.Report.Host.Name = "another-host"
			case "host revision":
				e.Report.Host.Revision = "111111111111"
			case "policy":
				e.Report.Policy = "different/1"
			case "protocol":
				e.Report.SchemaVersion = 2
			}
			if err := WriteJSON(filepath.Join(dir, next.Submission.Digest()+".json"), []compatibility.Evidence{e}); err != nil {
				t.Fatal(err)
			}
			if err := store.ImportCompatibility(index, plan, dir, plan.CheckerSHA256, plan.HostRevision); err == nil {
				t.Fatalf("accepted another %s", field)
			}
			if stored, err := store.Load(index); err != nil || len(stored) != 0 {
				t.Fatalf("failed import left evidence: %v, %v", stored, err)
			}
		})
	}
}

func TestImportRequiresTheExactOCIPrimaryLayers(t *testing.T) {
	entry := ociCandidate(t)
	entry.OCIPrimaryLayers = []string{strings.Repeat("1", 64), strings.Repeat("2", 64)}
	reports := make([]compatibility.Evidence, len(entry.OCIPrimaryLayers))
	for i, layer := range entry.OCIPrimaryLayers {
		e := importObservation(entry, "passed")
		e.Report.ArtifactSHA256, e.ReleaseSHA256 = layer, entry.Submission.Digest()
		reports[i] = e
	}
	for _, legacy := range []bool{false, true} {
		e := entry
		plan := importPlan(e)
		if legacy {
			plan.Targets[0].PrimaryLayers = e.OCIPrimaryLayers
			e.OCIPrimaryLayers = nil
		}
		index := Index{Entries: []Entry{e}}
		dir := t.TempDir()
		path := filepath.Join(dir, entry.Submission.Digest()+".json")
		store := EvidenceStore{Directory: t.TempDir()}
		first := reports[0]
		first.ObservedAt = first.ObservedAt.Add(-time.Second)
		if err := store.Add(index, first); err != nil {
			t.Fatal(err)
		}
		wrongLayer := reports[1]
		wrongLayer.Report.ArtifactSHA256 = strings.Repeat("f", 64)
		for _, wrong := range [][]compatibility.Evidence{reports[:1], {reports[0], reports[0]}, {reports[0], wrongLayer}, append(slices.Clone(reports), reports[0])} {
			if err := WriteJSON(path, wrong); err != nil {
				t.Fatal(err)
			}
			if err := store.ImportCompatibility(index, plan, dir, plan.CheckerSHA256, plan.HostRevision); err == nil {
				t.Fatalf("accepted incomplete or extra OCI reports (legacy %t)", legacy)
			}
		}
		if err := WriteJSON(path, reports); err != nil {
			t.Fatal(err)
		}
		if err := store.ImportCompatibility(index, plan, dir, plan.CheckerSHA256, plan.HostRevision); err != nil {
			t.Fatal(err)
		}
		if found, err := store.Load(index); err != nil || len(found) != 2 || !slices.ContainsFunc(found, func(e compatibility.Evidence) bool { return e.ObservedAt.Equal(first.ObservedAt) }) {
			t.Fatalf("expected original layer report and newly checked layer, got %v, %v", found, err)
		}
	}
}

func TestImportBindsPlanToPublisherPinsAndAcceptedRelease(t *testing.T) {
	entry := acceptedFixture(t)
	for _, field := range []string{"checker", "host", "tag", "plugin", "digest", "asset with layers", "different registered layers", "legacy OCI without planned layers"} {
		t.Run(field, func(t *testing.T) {
			release := entry
			if field == "different registered layers" || field == "legacy OCI without planned layers" {
				release = ociCandidate(t)
			}
			plan := importPlan(release)
			checker, host := plan.CheckerSHA256, plan.HostRevision
			switch field {
			case "checker":
				checker = strings.Repeat("f", 64)
			case "host":
				host = "111111111111"
			case "tag":
				plan.Targets[0].Version = "other"
			case "plugin":
				plan.Targets[0].Plugin = "github.com/publisher/other"
			case "digest":
				plan.Targets[0].SHA256 = strings.Repeat("e", 64)
			case "asset with layers", "different registered layers":
				plan.Targets[0].PrimaryLayers = []string{strings.Repeat("e", 64)}
			case "legacy OCI without planned layers":
				release.OCIPrimaryLayers = nil
			}
			results := t.TempDir()
			if err := os.WriteFile(filepath.Join(results, plan.Targets[0].SHA256+".unavailable"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			store := EvidenceStore{Directory: t.TempDir()}
			index := Index{Entries: []Entry{release}}
			if err := store.ImportCompatibility(index, plan, results, checker, host); err == nil {
				t.Fatalf("accepted a plan with a mismatched %s", field)
			}
		})
	}
}

func TestImportRejectsReportsTooLargeToReadBack(t *testing.T) {
	entry := acceptedFixture(t)
	plan := importPlan(entry)
	e := importObservation(entry, "passed")
	// The store's JSON encoder escapes each ampersand as six bytes.
	e.Report.Checks = slices.Repeat([]string{strings.Repeat("&", 256)}, 1500)
	var raw bytes.Buffer
	encoder := json.NewEncoder(&raw)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode([]compatibility.Evidence{e}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, entry.Submission.Digest()+".json"), raw.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	store := EvidenceStore{Directory: t.TempDir()}
	index := Index{Entries: []Entry{entry}}
	if err := store.ImportCompatibility(index, plan, dir, plan.CheckerSHA256, plan.HostRevision); err == nil || !strings.Contains(err.Error(), "serialized compatibility record") {
		t.Fatalf("unexpected import result: %v", err)
	}
	if stored, err := store.Load(index); err != nil || len(stored) != 0 {
		t.Fatalf("unreadable observation left in store: %v, %v", stored, err)
	}
}
