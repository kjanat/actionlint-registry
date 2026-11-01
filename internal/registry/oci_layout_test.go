package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeOCILayout(t *testing.T, variants ...[]byte) (string, string, map[string][]byte) {
	t.Helper()
	_, reference, objects := ociFixture(t, variants...)
	directory := t.TempDir()
	if err := os.MkdirAll(filepath.Join(directory, "blobs", "sha256"), 0o700); err != nil {
		t.Fatal(err)
	}
	for path, data := range objects {
		_, digest, ok := strings.Cut(path, "sha256:")
		if !ok {
			t.Fatal("fixture object lacks digest")
		}
		if err := os.WriteFile(filepath.Join(directory, "blobs", "sha256", digest), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, digest, ok := strings.Cut(reference, "@sha256:")
	if !ok {
		t.Fatal("fixture source lacks root digest")
	}
	root := objects["/v2/plugins/example/manifests/sha256:"+digest]
	var document ociDocument
	if err := json.Unmarshal(root, &document); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(filepath.Join(directory, "index.json"), ociDocument{SchemaVersion: 2, MediaType: ociIndex,
		Manifests: []ociDescriptor{descriptor(document.MediaType, root)}}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return directory, reference, objects
}

func TestLayoutCandidateSnapshotsOnlyVerifiedReachableGraph(t *testing.T) {
	layout, reference, objects := writeOCILayout(t, processBody(), processBody())
	unreferenced := descriptor("application/octet-stream", []byte("not part of the selected package"))
	if err := os.WriteFile(filepath.Join(layout, "blobs", "sha256", strings.TrimPrefix(unreferenced.Digest, "sha256:")), []byte("not part of the selected package"), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "candidate")
	candidate, err := ExportLayoutCandidate(t.Context(), reference, layout, output, EmptyIndex())
	if err != nil {
		t.Fatal(err)
	}
	if candidate.URL != reference || !strings.HasSuffix(reference, "@sha256:"+candidate.Artifact.SHA256) {
		t.Fatalf("candidate lost OCI root identity: %+v", candidate)
	}
	entries, err := os.ReadDir(filepath.Join(output, "oci-blobs"))
	if err != nil || len(entries) != len(objects) {
		t.Fatalf("wrong reachable snapshot: %d blobs, %d objects, %v", len(entries), len(objects), err)
	}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(output, "oci-blobs", entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := verifyOCI(data, "sha256:"+entry.Name(), -1); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := InspectLayout(ctx, reference, layout); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled layout inspection: %v", err)
	}
}

func TestLayoutCandidateRejectsIncompleteOrInconsistentGraphs(t *testing.T) {
	for _, mutation := range []string{"root missing", "layer missing", "layer corrupt", "root size", "root media", "root unregistered", "layout version"} {
		t.Run(mutation, func(t *testing.T) {
			layout, reference, _ := writeOCILayout(t, processBody())
			var index ociDocument
			if err := readRecord(filepath.Join(layout, "index.json"), &index); err != nil {
				t.Fatal(err)
			}
			primary := descriptor(ociProcess, processBody())
			path := filepath.Join(layout, "blobs", "sha256", strings.TrimPrefix(primary.Digest, "sha256:"))
			var err error
			switch mutation {
			case "root missing":
				err = os.Remove(filepath.Join(layout, "blobs", "sha256", strings.TrimPrefix(index.Manifests[0].Digest, "sha256:")))
			case "layer missing":
				err = os.Remove(path)
			case "layer corrupt":
				err = os.WriteFile(path, []byte("corrupt"), 0o600)
			case "root size":
				index.Manifests[0].Size++
				err = WriteJSON(filepath.Join(layout, "index.json"), index)
			case "root media":
				index.Manifests[0].MediaType = ociIndex
				err = WriteJSON(filepath.Join(layout, "index.json"), index)
			case "root unregistered":
				index.Manifests = nil
				err = WriteJSON(filepath.Join(layout, "index.json"), index)
			case "layout version":
				err = os.WriteFile(filepath.Join(layout, "oci-layout"), []byte(`{"imageLayoutVersion":"9.0.0"}`), 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			parent := t.TempDir()
			if _, err := ExportLayoutCandidate(t.Context(), reference, layout, filepath.Join(parent, "candidate"), EmptyIndex()); err == nil {
				t.Fatal("invalid OCI layout admitted")
			}
			entries, err := os.ReadDir(parent)
			if err != nil || len(entries) != 0 {
				t.Fatalf("failed layout export left staging: %v, %v", entries, err)
			}
		})
	}
}

func TestLayoutEmbeddedObjectsAreVerifiedAndSnapshotted(t *testing.T) {
	for _, mutation := range []string{"valid", "digest", "size", "base64", "empty"} {
		t.Run(mutation, func(t *testing.T) {
			layout, reference, _ := writeOCILayout(t, processBody())
			var index ociDocument
			if err := readRecord(filepath.Join(layout, "index.json"), &index); err != nil {
				t.Fatal(err)
			}
			var root ociDocument
			if err := readRecord(filepath.Join(layout, "blobs", "sha256", strings.TrimPrefix(index.Manifests[0].Digest, "sha256:")), &root); err != nil {
				t.Fatal(err)
			}
			root.Config.Data = []byte("{}")
			root.Layers[0].Data = processBody()
			for _, entry := range []ociDescriptor{*root.Config, root.Layers[0]} {
				if err := os.Remove(filepath.Join(layout, "blobs", "sha256", strings.TrimPrefix(entry.Digest, "sha256:"))); err != nil {
					t.Fatal(err)
				}
			}
			switch mutation {
			case "digest":
				root.Config.Data = []byte("[]")
			case "size":
				root.Config.Size++
			}
			data, err := json.Marshal(root)
			if err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "base64":
				data = bytes.Replace(data, []byte(`"data":"e30="`), []byte(`"data":"*"`), 1)
			case "empty":
				data = bytes.Replace(data, []byte(`"data":"e30="`), []byte(`"data":""`), 1)
			}
			selected := descriptor(ociManifest, data)
			if err := os.WriteFile(filepath.Join(layout, "blobs", "sha256", strings.TrimPrefix(selected.Digest, "sha256:")), data, 0o600); err != nil {
				t.Fatal(err)
			}
			index.Manifests = []ociDescriptor{selected}
			if err := WriteJSON(filepath.Join(layout, "index.json"), index); err != nil {
				t.Fatal(err)
			}
			prefix, _, _ := strings.Cut(reference, "@")
			reference = prefix + "@" + selected.Digest
			output := filepath.Join(t.TempDir(), "candidate")
			_, err = ExportLayoutCandidate(t.Context(), reference, layout, output, EmptyIndex())
			if mutation != "valid" {
				if err == nil {
					t.Fatal("forged embedded content admitted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range []ociDescriptor{*root.Config, root.Layers[0]} {
				data, err := os.ReadFile(filepath.Join(output, "oci-blobs", strings.TrimPrefix(entry.Digest, "sha256:")))
				if err != nil || !bytes.Equal(data, entry.Data) {
					t.Fatalf("embedded object missing from portable cache: %v", err)
				}
			}
		})
	}
}
