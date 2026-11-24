package registry

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"registry.actionlint.kjanat.dev/internal/artifact"
	"registry.actionlint.kjanat.dev/internal/compatibility"
)

func observation(entry Entry, outcome string) compatibility.Evidence {
	detail := ""
	if outcome != "passed" {
		detail = "This checker cannot run that contract."
	}
	return compatibility.Evidence{Report: compatibility.Report{SchemaVersion: 1, ArtifactSHA256: entry.Submission.SHA256, Host: compatibility.Host{Name: "test-host", Revision: "revision-a"}, Policy: "smoke/1", Outcome: outcome, Checks: []string{"host-abi"}, Detail: detail}, CheckerSHA256: strings.Repeat("a", 64), ObservedAt: time.Now().UTC()}
}
func TestCompatibilityEvidenceDoesNotRewriteRelease(t *testing.T) {
	entry := acceptedFixture(t)
	index := EmptyIndex()
	if err := index.Add(entry); err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	releases := Store{Directory: filepath.Join(directory, "plugins")}
	if err := releases.Merge(index); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(releases.Directory, entry.Receipt.PluginKey(), "versions", key(entry.Submission.Tag)+".json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	store := EvidenceStore{Directory: filepath.Join(directory, "compatibility")}
	for _, outcome := range []string{"passed", "failed", "unsupported"} {
		e := observation(entry, outcome)
		if err = store.Add(index, e); err != nil {
			t.Fatal(err)
		}
		if err = store.Add(index, e); err != nil {
			t.Fatal("duplicate report not idempotent:", err)
		}
	}
	observations, err := store.Load(index)
	if err != nil || len(observations) != 3 {
		t.Fatalf("observations: %v, %v", observations, err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("compatibility check rewrote release")
	}
	output := t.TempDir()
	if err = Export(index, output, nil, nil, observations...); err != nil {
		t.Fatal(err)
	}
	var manifest PluginManifest
	manifestPath := filepath.Join(output, "plugins", entry.Receipt.PluginKey(), "index.json")
	if err = readRecord(manifestPath, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Versions[0].Compatibility) != 3 {
		t.Fatal("missing compatibility links")
	}
	for _, link := range manifest.Versions[0].Compatibility {
		if _, err = os.Stat(filepath.Join(filepath.Dir(manifestPath), filepath.FromSlash(link.Report))); err != nil {
			t.Fatal("broken report link:", err)
		}
	}
	forged := observation(entry, "passed")
	forged.Report.ArtifactSHA256 = strings.Repeat("b", 64)
	if err = store.Add(index, forged); err == nil {
		t.Fatal("evidence attached to unknown artifact")
	}
	// Altering a record in place breaks its content-derived identity.
	name, err := evidenceName(observations[0])
	if err != nil {
		t.Fatal(err)
	}
	changed := observations[0]
	changed.Report.Host.Revision = "forged"
	if err = WriteJSON(filepath.Join(store.Directory, entry.Submission.SHA256, name), changed); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Load(index); err == nil {
		t.Fatal("altered host identity accepted at original path")
	}
}
func TestUnknownABIIsUntestedWithoutReports(t *testing.T) {
	entry := acceptedFixture(t)
	index := EmptyIndex()
	if err := index.Add(entry); err != nil {
		t.Fatal(err)
	}
	output := t.TempDir()
	if err := Export(index, output, nil, nil); err != nil {
		t.Fatal(err)
	}
	var manifest PluginManifest
	if err := readRecord(filepath.Join(output, "plugins", entry.Receipt.PluginKey(), "index.json"), &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Versions[0].Compatibility == nil || len(manifest.Versions[0].Compatibility) != 0 {
		t.Fatal("unknown contract was presented as tested")
	}
}
func TestLegacyRecordsRetainTheirOriginalBytes(t *testing.T) {
	entry := acceptedFixture(t)
	declared := entry.Artifact
	entry.RecordVersion = 0
	entry.Artifact = nil
	entry.Validation = &LegacyValidation{Kind: declared.Kind, PluginID: declared.PluginID, PluginVersion: declared.PluginVersion, Repository: declared.Repository, Metadata: declared.Metadata, Contract: "wasm-core-json/1", Rules: []string{"example"}, Checks: []string{"host-abi"}, HostCommit: strings.Repeat("a", 40), PolicyVersion: "1"}
	index := EmptyIndex()
	if err := index.Add(entry); err != nil {
		t.Fatal(err)
	}
	store := Store{Directory: filepath.Join(t.TempDir(), "plugins")}
	if err := store.Merge(index); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(store.Directory, entry.Receipt.PluginKey(), "versions", key(entry.Submission.Tag)+".json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Read and export a historical record without adding modern fields.
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if err = Export(loaded, t.TempDir(), nil, nil); err != nil {
		t.Fatal(err)
	}
	if err = store.Merge(loaded); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) || bytes.Contains(after, []byte(`"record_version"`)) || bytes.Contains(after, []byte(`"artifact"`)) {
		t.Fatal("historical record changed")
	}
}
func TestRegistryHasNoHostSDKDependency(t *testing.T) {
	cmd := exec.CommandContext(t.Context(), "go", "list", "-deps", "./cmd/registry")
	cmd.Dir = "../.."
	data, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if strings.HasPrefix(line, "actionlint.kjanat.dev/") || strings.Contains(line, "/adapters/") {
			t.Fatalf("registry imports host SDK: %s", line)
		}
	}
}
func TestCompatibilityReportStrictProtocol(t *testing.T) {
	v1 := observation(acceptedFixture(t), "passed").Report
	v2 := v1
	v2.SchemaVersion, v2.RunnerAsOf = 2, "2026-12-08"
	v3 := v2
	v3.SchemaVersion = 3
	listed := v3
	listed.Imports, listed.Exports = []string{}, []string{"kjanat:actionlint/analyzer@0.2.0"}
	for _, valid := range []compatibility.Report{v1, v2, v3, listed} {
		if err := valid.Validate(); err != nil {
			t.Fatalf("valid protocol %d report rejected: %v", valid.SchemaVersion, err)
		}
	}
	for name, mutate := range map[string]func(*compatibility.Report){
		"unknown protocol":           func(r *compatibility.Report) { r.SchemaVersion = 4 },
		"outcome":                    func(r *compatibility.Report) { r.Outcome = "maybe" },
		"host":                       func(r *compatibility.Report) { r.Host.Revision = "" },
		"policy":                     func(r *compatibility.Report) { r.Policy = "" },
		"checks":                     func(r *compatibility.Report) { r.Checks = nil },
		"protocol 3 without date":    func(r *compatibility.Report) { r.RunnerAsOf = "" },
		"impossible date":            func(r *compatibility.Report) { r.RunnerAsOf = "2026-02-30" },
		"short date":                 func(r *compatibility.Report) { r.RunnerAsOf = "2026-12-8" },
		"protocol 1 with date":       func(r *compatibility.Report) { r.SchemaVersion = 1 },
		"protocol 2 with interfaces": func(r *compatibility.Report) { r.SchemaVersion = 2 },
		"imports without exports":    func(r *compatibility.Report) { r.Exports = nil },
		"exports without imports":    func(r *compatibility.Report) { r.Imports = nil },
		"empty interface name":       func(r *compatibility.Report) { r.Exports = []string{""} },
		"multiline interface name":   func(r *compatibility.Report) { r.Imports = []string{"wasi:cli/environment@0.2.0\nexport"} },
		"long interface name":        func(r *compatibility.Report) { r.Imports = []string{strings.Repeat("a", 513)} },
		"too many interfaces":        func(r *compatibility.Report) { r.Exports = slices.Repeat([]string{"a"}, 4097) },
	} {
		changed := listed
		mutate(&changed)
		if err := changed.Validate(); err == nil {
			data, _ := json.Marshal(changed)
			t.Fatalf("%s: invalid report accepted: %s", name, data)
		}
	}
}

func TestEvidenceNamesTheReleaseOfACheckedLayer(t *testing.T) {
	evidence := observation(acceptedFixture(t), "passed")
	if evidence.Release() != evidence.Report.ArtifactSHA256 {
		t.Fatalf("release asset evidence names %s", evidence.Release())
	}
	evidence.ReleaseSHA256 = strings.Repeat("c", 64)
	if err := evidence.Validate(); err != nil || evidence.Release() != evidence.ReleaseSHA256 {
		t.Fatalf("layer evidence release %s: %v", evidence.Release(), err)
	}
	for _, release := range []string{evidence.Report.ArtifactSHA256, "sha256:" + strings.Repeat("c", 64), strings.Repeat("C", 64)} {
		changed := evidence
		changed.ReleaseSHA256 = release
		if err := changed.Validate(); err == nil {
			t.Fatalf("accepted release digest %q", release)
		}
	}
}

func componentMetadata(platform string) string {
	return `{"metadata_version":1,"transport":"wasm-component","id":"example","name":"Example","description":"Example for ` + platform + `","license":"MIT","repository":"https://github.com/publisher/plugin","plugin_version":"1.0.0","interface":"kjanat:actionlint/analyzer@0.2.0","wit_sha256":"` + strings.Repeat("a", 64) + `"}`
}

func exportedVersion(t *testing.T, index Index, evidence []compatibility.Evidence) map[string]json.RawMessage {
	t.Helper()
	output := t.TempDir()
	if err := Export(index, output, nil, nil, evidence...); err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Versions []map[string]json.RawMessage `json:"versions"`
	}
	data, err := os.ReadFile(filepath.Join(output, "plugins", index.Entries[0].PluginKey(), "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(data, &manifest); err != nil || len(manifest.Versions) != 1 {
		t.Fatalf("manifest %s: %v", data, err)
	}
	return manifest.Versions[0]
}

func componentAssetEntry(t *testing.T) Entry {
	t.Helper()
	entry := acceptedFixture(t)
	entry.Submission.Kind = "component"
	entry.Receipt.Submission = entry.Submission
	entry.Artifact = &artifact.Declaration{Kind: "component", SHA256: entry.Submission.SHA256, PluginID: "example", PluginVersion: "1.0.0", Repository: "https://github.com/publisher/plugin", Contract: "kjanat:actionlint/analyzer@0.2.0#sha256=" + strings.Repeat("a", 64), Metadata: json.RawMessage(componentMetadata("wasm"))}
	return entry
}

func listedObservation(entry Entry, exports ...string) compatibility.Evidence {
	evidence := observation(entry, "passed")
	evidence.Report.SchemaVersion, evidence.Report.RunnerAsOf = 3, "2026-12-08"
	evidence.Report.Imports, evidence.Report.Exports = []string{}, exports
	return evidence
}

func TestExportListsComponentInterfaces(t *testing.T) {
	component, core := componentAssetEntry(t), acceptedFixture(t)
	analyzer, runner := "kjanat:actionlint/analyzer@0.2.0", "kjanat:actionlint/runner-provider@0.3.0"
	for name, test := range map[string]struct {
		entry    Entry
		evidence []compatibility.Evidence
		exports  []string
	}{
		"component with interfaces":      {component, []compatibility.Evidence{observation(component, "passed"), listedObservation(component, analyzer)}, []string{analyzer}},
		"component without interfaces":   {component, []compatibility.Evidence{observation(component, "passed")}, nil},
		"component without evidence":     {component, nil, nil},
		"component with disagreement":    {component, []compatibility.Evidence{listedObservation(component, analyzer), listedObservation(component, runner)}, nil},
		"core module with listed report": {core, []compatibility.Evidence{listedObservation(core, analyzer)}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			index := EmptyIndex()
			if err := index.Add(test.entry); err != nil {
				t.Fatal(err)
			}
			version := exportedVersion(t, index, test.evidence)
			imports, hasImports := version["imports"]
			exported, hasExports := version["exports"]
			if test.exports == nil {
				if hasImports || hasExports {
					t.Fatalf("published interfaces without agreeing component facts: %s %s", imports, exported)
				}
				return
			}
			var gotImports, gotExports []string
			if err := errors.Join(json.Unmarshal(imports, &gotImports), json.Unmarshal(exported, &gotExports)); err != nil || gotImports == nil || len(gotImports) != 0 || !slices.Equal(gotExports, test.exports) {
				t.Fatalf("imports %s exports %s: %v", imports, exported, err)
			}
		})
	}
}
