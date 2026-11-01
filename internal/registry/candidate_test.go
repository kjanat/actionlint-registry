package registry

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"registry.actionlint.kjanat.dev/internal/artifact"
)

// A local rehearsal must export the packaged bytes without inventing publication
// evidence. Reading the exported catalogue back checks its paths, metadata and
// digest; changing the input afterward must not alter the installable snapshot.
func TestCandidateExportsSnapshotWithoutPublication(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "plugin.wasm")
	body := []byte(sampleBody())
	if err := os.WriteFile(input, body, 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "candidate")
	candidate, err := ExportCandidate(t.Context(), input, output, EmptyIndex())
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Artifact.SHA256 != sampleSubmission().SHA256 {
		t.Fatal("wrong snapshot digest")
	}
	var catalog Catalog
	if err = readRecord(filepath.Join(output, "index.json"), &catalog); err != nil {
		t.Fatal(err)
	}
	if catalog.Source != "candidate" || catalog.Statuses != "" || len(catalog.Plugins) != 1 {
		t.Fatalf("unexpected catalogue: %+v", catalog)
	}
	var manifest CandidateManifest
	manifestPath := filepath.Join(output, filepath.FromSlash(catalog.Plugins[0].Manifest))
	if err = readRecord(manifestPath, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Source != "candidate" || manifest.Name != "github.com/publisher/plugin" || len(manifest.Versions) != 1 || manifest.Versions[0].Version != "v1.0.0" {
		t.Fatalf("unexpected manifest: %+v", manifest)
	}
	var record Candidate
	if err = readRecord(filepath.Join(filepath.Dir(manifestPath), filepath.FromSlash(manifest.Versions[0].Record)), &record); err != nil {
		t.Fatal(err)
	}
	if record.Source != "candidate" || record.Artifact.SHA256 != candidate.Artifact.SHA256 {
		t.Fatal("record differs from inspected bytes")
	}
	if err = os.WriteFile(input, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := os.ReadFile(filepath.Join(output, filepath.FromSlash(record.URL)))
	if err != nil || !bytes.Equal(snapshot, body) {
		t.Fatal("candidate did not snapshot input", err)
	}
	if _, err = (Store{Directory: filepath.Join(output, "plugins")}).Load(); err == nil {
		t.Fatal("candidate accepted as publication records")
	}
	if err = os.WriteFile(input, body, 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(output, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ExportCandidate(t.Context(), input, output, EmptyIndex()); err == nil {
		t.Fatal("replaced existing output")
	}
	after, err := os.ReadFile(filepath.Join(output, "index.json"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed export changed catalogue")
	}
}

// Existing registrations must constrain a candidate before a release is made.
// These cases reject a changed plugin identity and replacement bytes for an
// accepted version, without creating a catalogue that CI could accidentally use.
func TestCandidateRejectsRegisteredConflicts(t *testing.T) {
	for _, mutation := range []string{"identity", "version"} {
		t.Run(mutation, func(t *testing.T) {
			entry := acceptedFixture(t)
			body := sampleBody()
			if mutation == "identity" {
				body = strings.Replace(body, `"id":"example"`, `"id":"changed"`, 1)
			} else {
				body = strings.Replace(body, "Example plugin", "Changed plugin", 1)
			}
			root := t.TempDir()
			input, output := filepath.Join(root, "plugin.wasm"), filepath.Join(root, "candidate")
			if err := os.WriteFile(input, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := ExportCandidate(t.Context(), input, output, Index{SchemaVersion: 1, Entries: []Entry{entry}}); err == nil {
				t.Fatal("registered conflict accepted")
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatal("rejected candidate left a catalogue")
			}
		})
	}
}

func TestCandidateExportsPinnedOCIRoot(t *testing.T) {
	inspector, reference, _ := ociFixture(t, processBody())
	root := t.TempDir()
	output := filepath.Join(root, "candidate")
	candidate, err := exportCandidate(t.Context(), reference, output, EmptyIndex(), func(ctx context.Context, input, _ string) (artifact.Declaration, error) {
		return inspector.Inspect(ctx, input)
	})
	if err != nil {
		t.Fatal(err)
	}
	distribution, err := OCIReference(reference)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.URL != reference || candidate.Artifact.SHA256 != distribution.digest {
		t.Fatalf("candidate lost pinned root identity: %+v", candidate)
	}
	if candidate.Artifact.Kind != "manifest" {
		t.Fatalf("wrong artifact kind: %+v", candidate.Artifact)
	}
	var catalog Catalog
	if err = readRecord(filepath.Join(output, "index.json"), &catalog); err != nil {
		t.Fatal(err)
	}
	if len(catalog.Plugins) != 1 || catalog.Plugins[0].Name != "github.com/publisher/plugin" {
		t.Fatalf("wrong package selector: %+v", catalog.Plugins)
	}
	var manifest CandidateManifest
	if err = readRecord(filepath.Join(output, filepath.FromSlash(catalog.Plugins[0].Manifest)), &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.PluginID != "example" || manifest.Name != catalog.Plugins[0].Name {
		t.Fatalf("candidate identity changed: %+v", manifest)
	}
	var record Candidate
	manifestPath := filepath.Join(output, filepath.FromSlash(catalog.Plugins[0].Manifest))
	if err = readRecord(filepath.Join(filepath.Dir(manifestPath), filepath.FromSlash(manifest.Versions[0].Record)), &record); err != nil {
		t.Fatal(err)
	}
	if record.URL != reference || record.Artifact.SHA256 != candidate.Artifact.SHA256 {
		t.Fatalf("record lost root digest reference: %+v", record)
	}
	if _, err = os.Stat(filepath.Join(output, "artifacts")); !os.IsNotExist(err) {
		t.Fatal("OCI primary layer was copied as a root-digest artifact")
	}
}

func TestCandidateRejectsInvalidOCIWithoutChangingOutputOrStaging(t *testing.T) {
	root := t.TempDir()
	output := filepath.Join(root, "candidate")
	if err := os.Mkdir(output, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(output, "sentinel")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	valid := "oci://registry.example/plugins/example@sha256:" + strings.Repeat("a", 64)
	badReferences := []string{
		"oci://registry.example/plugins/example:latest",
		"oci://user@registry.example/plugins/example@sha256:" + strings.Repeat("a", 64),
		"oci://registry.example/plugins/example@sha256:" + strings.Repeat("A", 64),
		"oci://registry.example/plugins/example@sha256:" + strings.Repeat("a", 64) + "#fragment",
	}
	for _, reference := range badReferences {
		if _, err := ExportCandidate(t.Context(), reference, output, EmptyIndex()); err == nil {
			t.Fatalf("invalid reference accepted: %s", reference)
		}
	}
	failedInspector := func(context.Context, string, string) (artifact.Declaration, error) {
		return artifact.Declaration{}, errors.New("fixture inspection failure")
	}
	if _, err := exportCandidate(t.Context(), valid, output, EmptyIndex(), failedInspector); err == nil {
		t.Fatal("inspection failure accepted")
	}
	data, err := os.ReadFile(sentinel)
	if err != nil || string(data) != "keep" {
		t.Fatal("failed export changed existing catalogue", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 1 || entries[0].Name() != "candidate" {
		t.Fatalf("failed export left staging data: %+v, %v", entries, err)
	}
}
