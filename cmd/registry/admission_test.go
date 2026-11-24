package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
	"registry.actionlint.kjanat.dev/internal/compatibility"
	"registry.actionlint.kjanat.dev/internal/registry"
)

type releaseTransport func(*http.Request) (*http.Response, error)

func (f releaseTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Exercise the admission command with release HTTP fixtures. Admission must read
// existing registrations even when it writes elsewhere, and publication must
// report a conflict introduced after validation without changing the real store.
func TestAdmissionDeltaAndPublicationConflict(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the admission workflow and its fake checker run on Linux")
	}
	t.Setenv("GH_TOKEN", "test-token")
	root := t.TempDir()
	storePath := filepath.Join(root, "registry/plugins")
	candidatePath := filepath.Join(root, "candidate/plugins")
	receiptPath := filepath.Join(root, "handoff/receipt.json")
	workflow, err := os.ReadFile("../../.github/workflows/admission.yml")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Jobs map[string]struct {
			Steps []struct{ ID, Run string }
		}
	}
	if err = yaml.Unmarshal(workflow, &document); err != nil {
		t.Fatal(err)
	}
	workflowArguments := func(job, step, prefix string) []string {
		t.Helper()
		for _, value := range document.Jobs[job].Steps {
			if value.ID != step {
				continue
			}
			command, ok := strings.CutPrefix(value.Run, prefix)
			if !ok {
				t.Fatalf("unexpected %s command: %s", step, value.Run)
			}
			args := strings.Fields(command)
			for i := 1; i < len(args); i += 2 {
				if i+1 >= len(args) {
					t.Fatal("workflow flag has no value")
				}
				args[i+1] = filepath.Join(root, args[i+1])
			}
			return args
		}
		t.Fatalf("workflow step missing: %s/%s", job, step)
		return nil
	}
	admissionArgs := workflowArguments("validate", "admission", "bash scripts/validate.sh ./registry-cli ")
	mergeArgs := workflowArguments("publish", "merge", "go run ./cmd/registry ")
	data, err := os.ReadFile("../../internal/registry/testdata/github-receipt.json")
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := registry.ParseReceipt(data)
	if err != nil {
		t.Fatal(err)
	}
	var wasm []byte
	previous := http.DefaultTransport
	http.DefaultTransport = releaseTransport(func(r *http.Request) (*http.Response, error) {
		var body string
		switch r.URL.Host + r.URL.Path {
		case "api.github.com/repos/publisher/plugin":
			body = `{"id":10,"full_name":"publisher/plugin","private":false,"owner":{"id":5}}`
		case "api.github.com/repos/publisher/plugin/releases/tags/" + receipt.Submission.Tag:
			body = fmt.Sprintf(`{"id":20,"tag_name":%q,"immutable":true,"published_at":"2026-01-01T00:00:00Z","assets":[{"id":30,"name":"plugin.wasm","state":"uploaded","size":%d,"digest":%q,"browser_download_url":%q}]}`,
				receipt.Submission.Tag, len(wasm), "sha256:"+receipt.Submission.SHA256,
				"https://github.com/publisher/plugin/releases/download/"+receipt.Submission.Tag+"/plugin.wasm")
		case "api.github.com/repos/publisher/plugin/commits/" + receipt.Submission.Tag:
			body = `{"sha":"` + receipt.Identity.Commit + `"}`
		case "github.com/publisher/plugin/releases/download/" + receipt.Submission.Tag + "/plugin.wasm":
			body = string(wasm)
		default:
			return nil, fmt.Errorf("unexpected release request: %s", r.URL)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})
	t.Cleanup(func() { http.DefaultTransport = previous })
	prepare := func(version, pluginID string) {
		t.Helper()
		metadata := fmt.Sprintf(`{"metadata_version":1,"abi_version":1,"transport":"wasm-core-json","id":%q,"name":"Example","description":"Example plugin","license":"MIT","repository":"https://github.com/publisher/plugin","plugin_version":%q}`, pluginID, version)
		section := append([]byte{17}, []byte("actionlint.plugin")...)
		section = append(section, metadata...)
		wasm = []byte{0, 97, 115, 109, 1, 0, 0, 0, 0}
		for size := len(section); ; size >>= 7 {
			value := byte(size & 127)
			if size >= 128 {
				value |= 128
			}
			wasm = append(wasm, value)
			if size < 128 {
				break
			}
		}
		wasm = append(wasm, section...)
		digest := sha256.Sum256(wasm)
		receipt.Submission.SHA256 = hex.EncodeToString(digest[:])
		report := fmt.Sprintf(`{"schema_version":2,"artifact_sha256":%q,"host":{"name":"actionlint","revision":"test"},"policy":"actionlint-smoke/1","outcome":"passed","checks":["metadata-v1"],"runner_as_of":"%%s"}`, receipt.Submission.SHA256)
		script := "#!/bin/sh\nif [ \"$1\" = --protocol ]; then printf '2\\n'; exit 0; fi\nif [ \"$1\" = --runner-as-of ]; then date=$2; shift 2; fi\n[ \"$#\" -eq 1 ] && [ -f \"$1\" ] || exit 1\nprintf '" + report + "\\n' \"$date\"\n"
		if err := os.WriteFile(filepath.Join(root, "registry-checker"), []byte(script), 0o700); err != nil {
			t.Fatal(err)
		}
		receipt.Submission.Tag = "v" + version
		receipt.Identity.Ref = "refs/tags/v" + version
		receipt.AuthorizedAt = time.Now().UTC()
		if err := registry.WriteJSON(receiptPath, receipt); err != nil {
			t.Fatal(err)
		}
	}
	prepare("1.0.0", "example")
	if err = run(t.Context(), []string{"admit", "--receipt", receiptPath, "--store", storePath}); err != nil {
		t.Fatal(err)
	}
	original, err := (registry.Store{Directory: storePath}).Load()
	if err != nil {
		t.Fatal(err)
	}
	recheckReleaseWithStoredDate(t, root, storePath, original.Entries[0], wasm)
	prepare("1.1.0", "different")
	if err = run(t.Context(), admissionArgs); err == nil || registry.FailureDisposition(err) != "rejected" {
		t.Fatalf("changed identity escaped existing registrations: %v", err)
	}
	if _, err = os.Stat(candidatePath); !os.IsNotExist(err) {
		t.Fatal("rejected candidate wrote an output store")
	}
	prepare("1.1.0", "example")
	admissionStart := time.Now()
	if err = run(t.Context(), admissionArgs); err != nil {
		t.Fatal(err)
	}
	unchanged, err := (registry.Store{Directory: storePath}).Load()
	if err != nil {
		t.Fatal(err)
	}
	before, _ := json.Marshal(original)
	after, _ := json.Marshal(unchanged)
	if !bytes.Equal(before, after) {
		t.Fatal("admission mutated existing registrations")
	}
	candidate, err := (registry.Store{Directory: candidatePath}).Load()
	if err != nil || len(candidate.Entries) != 1 || candidate.Entries[0].Submission.Tag != "v1.1.0" {
		t.Fatalf("wrong admission delta: %+v, %v", candidate, err)
	}
	admitted, err := (registry.EvidenceStore{Directory: filepath.Join(root, "candidate/compatibility")}).Load(candidate)
	if err != nil || len(admitted) != 1 || !dayOfCheck(admissionStart, admitted[0].Report.RunnerAsOf) {
		t.Fatalf("admission did not store its dated evidence: %+v, %v", admitted, err)
	}
	defaultEvidenceAdmission(t, root, admissionArgs, candidate.Entries[0].Submission.SHA256)
	if err = run(t.Context(), []string{"merge", "--store", filepath.Join(root, "bare/plugins"), "--candidate", candidatePath}); err == nil || !strings.Contains(err.Error(), "no compatibility evidence") {
		t.Fatalf("merge accepted a new version without evidence: %v", err)
	}
	if bare, err := (registry.Store{Directory: filepath.Join(root, "bare/plugins")}).Load(); err != nil || len(bare.Entries) != 0 {
		t.Fatalf("merge without evidence wrote records: %+v, %v", bare, err)
	}
	if err = (registry.Store{Directory: filepath.Join(root, "accepted/candidate/plugins")}).Merge(candidate); err != nil {
		t.Fatal(err)
	}
	if err = (registry.EvidenceStore{Directory: filepath.Join(root, "accepted/candidate/compatibility")}).Add(candidate, admitted[0]); err != nil {
		t.Fatal(err)
	}
	published := filepath.Join(root, "published")
	if err = run(t.Context(), []string{"merge", "--store", filepath.Join(published, "plugins"), "--candidate", filepath.Join(root, "accepted/candidate/plugins"),
		"--compatibility", filepath.Join(published, "compatibility"), "--candidate-compatibility", filepath.Join(root, "accepted/candidate/compatibility")}); err != nil {
		t.Fatal(err)
	}
	merged, err := (registry.Store{Directory: filepath.Join(published, "plugins")}).Load()
	if err != nil {
		t.Fatal(err)
	}
	if stored, err := (registry.EvidenceStore{Directory: filepath.Join(published, "compatibility")}).Load(merged); err != nil || len(stored) != 1 || stored[0].Report.RunnerAsOf != admitted[0].Report.RunnerAsOf {
		t.Fatalf("merge did not publish the admission evidence: %+v, %v", stored, err)
	}
	conflict := candidate.Entries[0]
	conflict.AssetID++
	if err = (registry.Store{Directory: storePath}).Merge(registry.Index{SchemaVersion: 1, Entries: []registry.Entry{conflict}}); err != nil {
		t.Fatal(err)
	}
	err = run(t.Context(), mergeArgs)
	if err == nil || registry.FailureDisposition(err) != "rejected" {
		t.Fatalf("publication conflict was not rejected: %v", err)
	}
	if _, err = os.Stat(filepath.Join(root, "registry/compatibility", candidate.Entries[0].Submission.SHA256)); !os.IsNotExist(err) {
		t.Fatalf("rejected publication stored admission evidence: %v", err)
	}
	data, err = os.ReadFile(filepath.Join(root, "reports/publication.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report registry.Report
	if err = json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.Mode != "merge" || report.SubmissionID != receipt.ID || len(report.Accepted) != 0 || len(report.Rejected) != 1 || report.Rejected[0].Disposition != "rejected" {
		t.Fatalf("publication failure has no actionable report: %+v", report)
	}
}

func recheckReleaseWithStoredDate(t *testing.T, root, storePath string, entry registry.Entry, wasm []byte) {
	t.Helper()
	artifactPath := filepath.Join(root, "accepted.wasm")
	if err := os.WriteFile(artifactPath, wasm, 0o600); err != nil {
		t.Fatal(err)
	}
	argsLog := filepath.Join(root, "checker-args.log")
	compatibilityPath := filepath.Join(root, "registry/compatibility")
	index, err := (registry.Store{Directory: storePath}).Load()
	if err != nil {
		t.Fatal(err)
	}
	const stored = "2026-12-10"
	seed := compatibility.Evidence{Report: compatibility.Report{SchemaVersion: 2, ArtifactSHA256: entry.Submission.SHA256, Host: compatibility.Host{Name: "actionlint", Revision: "earlier"}, Policy: "actionlint-smoke/1", Outcome: "passed", Checks: []string{"metadata-v1"}, RunnerAsOf: stored},
		CheckerSHA256: strings.Repeat("a", 64), ObservedAt: time.Now().UTC().Add(-time.Hour)}
	if err = (registry.EvidenceStore{Directory: compatibilityPath}).Add(index, seed); err != nil {
		t.Fatal(err)
	}
	report := fmt.Sprintf(`{"schema_version":2,"artifact_sha256":%q,"host":{"name":"actionlint","revision":"test"},"policy":"actionlint-smoke/1","outcome":"passed","checks":["metadata-v1"],"runner_as_of":"%%s"}`, entry.Submission.SHA256)
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '" + argsLog + "'\nif [ \"$1\" = --protocol ]; then printf '2\\n'; exit 0; fi\n[ \"$1\" = --runner-as-of ] || exit 1\ndate=$2\nprintf '" + report + "\\n' \"$date\"\n"
	checker := filepath.Join(root, "dated-checker")
	if err := os.WriteFile(checker, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	args := []string{"check", "--store", storePath, "--compatibility", compatibilityPath, "--checker", checker, "--artifact", artifactPath, "--plugin", entry.Name(), "--version", entry.Submission.Tag}
	for range 2 {
		if err := run(t.Context(), args); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(argsLog)
	if err != nil {
		t.Fatal(err)
	}
	calls := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(calls) != 4 || calls[0] != "--protocol" || !strings.HasPrefix(calls[1], "--runner-as-of "+stored+" ") || calls[2] != "--protocol" || !strings.HasPrefix(calls[3], "--runner-as-of "+stored+" ") {
		t.Fatalf("recheck did not replay the stored runner date: %q", calls)
	}
}

func dayOfCheck(start time.Time, date string) bool {
	return date == start.UTC().Format(time.DateOnly) || date == time.Now().UTC().Format(time.DateOnly)
}

// defaultEvidenceAdmission repeats the workflow's admission without
// --compatibility, with --candidate spelled relative to the working directory.
func defaultEvidenceAdmission(t *testing.T, root string, admissionArgs []string, digest string) {
	t.Helper()
	for name, test := range map[string]struct{ cwd, candidate, store string }{
		"trailing slash": {root, "trailing/plugins/", filepath.Join(root, "trailing/plugins")},
		"dot":            {filepath.Join(root, "dot/plugins"), ".", filepath.Join(root, "dot/plugins")},
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.MkdirAll(test.cwd, 0o755); err != nil {
				t.Fatal(err)
			}
			t.Chdir(test.cwd)
			var args []string
			for i := 0; i < len(admissionArgs); i++ {
				switch admissionArgs[i] {
				case "--compatibility":
					i++
				case "--candidate":
					args = append(args, "--candidate", test.candidate)
					i++
				default:
					args = append(args, admissionArgs[i])
				}
			}
			if err := run(t.Context(), args); err != nil {
				t.Fatal(err)
			}
			candidate, err := (registry.Store{Directory: test.store}).Load()
			if err != nil {
				t.Fatal(err)
			}
			sibling := filepath.Join(filepath.Dir(test.store), "compatibility")
			if evidence, err := (registry.EvidenceStore{Directory: sibling}).Load(candidate); err != nil || len(evidence) != 1 {
				t.Fatalf("admission without --compatibility did not use %s: %+v, %v", sibling, evidence, err)
			}
			for _, path := range []string{filepath.Join(test.store, "compatibility"), filepath.Join("registry/compatibility", digest)} {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatalf("candidate admission wrote evidence to %s: %v", path, err)
				}
			}
		})
	}
}

func TestAdmissionWorkflowCarriesEvidence(t *testing.T) {
	workflow, err := os.ReadFile("../../.github/workflows/admission.yml")
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Jobs map[string]struct {
			Steps []struct {
				ID, Name, Uses, Run string
				With                map[string]any
			}
		}
	}
	if err = yaml.Unmarshal(workflow, &document); err != nil {
		t.Fatal(err)
	}
	uploads, downloads, merges, commits := false, false, false, false
	for _, step := range document.Jobs["validate"].Steps {
		if path, ok := step.With["path"].(string); ok && step.Name == "Transfer accepted records and lease" {
			uploads = slices.Contains(strings.Fields(path), "candidate/compatibility/")
		}
	}
	for _, step := range document.Jobs["publish"].Steps {
		switch {
		case strings.HasPrefix(step.Uses, "actions/download-artifact@"):
			downloads = step.With["name"] == "validated-submission" && step.With["path"] == "accepted"
		case step.ID == "merge":
			fields := strings.Fields(step.Run)
			flag := func(name, value string) bool {
				index := slices.Index(fields, name)
				return index >= 0 && index+1 < len(fields) && fields[index+1] == value
			}
			merges = flag("--compatibility", "registry/compatibility") && flag("--candidate-compatibility", "accepted/candidate/compatibility")
		case step.Name == "Commit accepted records as the registry bot":
			commits = slices.ContainsFunc(strings.Split(step.Run, "\n"), func(line string) bool { return strings.TrimSpace(line) == "git add -- registry/compatibility" })
		}
	}
	if !uploads || !downloads || !merges || !commits {
		t.Fatalf("admission workflow drops evidence: upload=%t download=%t merge=%t commit=%t", uploads, downloads, merges, commits)
	}
}

type layoutDescriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int    `json:"size"`
}

func TestCheckOfUnpublishedOCIChecksEveryPlatformLayer(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the fake checker hashes layers with sha256sum")
	}
	root := t.TempDir()
	layout := filepath.Join(root, "layout")
	if err := os.MkdirAll(filepath.Join(layout, "blobs", "sha256"), 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(mediaType string, data []byte) layoutDescriptor {
		sum := sha256.Sum256(data)
		digest := hex.EncodeToString(sum[:])
		if err := os.WriteFile(filepath.Join(layout, "blobs", "sha256", digest), data, 0o600); err != nil {
			t.Fatal(err)
		}
		return layoutDescriptor{MediaType: mediaType, Digest: "sha256:" + digest, Size: len(data)}
	}
	document := func(value any) []byte {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	const manifestType, indexType = "application/vnd.oci.image.manifest.v1+json", "application/vnd.oci.image.index.v1+json"
	config := write("application/vnd.oci.empty.v1+json", []byte("{}"))
	var manifests, layers []layoutDescriptor
	for _, platform := range []string{"linux", "darwin"} {
		metadata := `{"metadata_version":1,"transport":"wasm-component","id":"example","name":"Example","description":"Example","license":"MIT","repository":"https://github.com/publisher/plugin","plugin_version":"1.0.0","interface":"kjanat:actionlint/analyzer@0.2.0","wit_sha256":"` + strings.Repeat("a", 64) + `"}`
		section := append([]byte{17}, "actionlint.plugin"...)
		section = append(section, metadata...)
		component := append([]byte("\x00asm\x0d\x00\x01\x00\x00"), byte(len(section)&127)|128, byte(len(section)>>7))
		component = append(component, section...)
		label := append([]byte{22}, "registry-test.platform"...)
		component = append(component, 0, byte(len(label)+len(platform)))
		component = append(component, label...)
		layer := write("application/wasm", append(component, platform...))
		layers = append(layers, layer)
		manifests = append(manifests, write(manifestType, document(map[string]any{"schemaVersion": 2, "mediaType": manifestType, "config": config, "layers": []layoutDescriptor{layer}})))
	}
	index := write(indexType, document(map[string]any{"schemaVersion": 2, "mediaType": indexType, "manifests": manifests}))
	if err := os.WriteFile(filepath.Join(layout, "index.json"), document(map[string]any{"schemaVersion": 2, "mediaType": indexType, "manifests": []layoutDescriptor{index}}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(layout, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	report := `{"schema_version":3,"artifact_sha256":"%s","host":{"name":"actionlint","revision":"test"},"policy":"actionlint-smoke/1","outcome":"passed","checks":["sample"],"runner_as_of":"%s","imports":[],"exports":["kjanat:actionlint/analyzer@0.2.0"]}`
	script := "#!/bin/sh\nif [ \"$1\" = --protocol ]; then printf '3\\n'; exit 0; fi\nif [ \"$1\" = --runner-as-of ]; then date=$2; shift 2; fi\n[ \"$#\" -eq 1 ] && [ -f \"$1\" ] || exit 1\nset -- $(sha256sum \"$1\")\nprintf '" + report + "\\n' \"$1\" \"$date\"\n"
	checker := filepath.Join(root, "checker")
	if err := os.WriteFile(checker, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	store := filepath.Join(root, "plugins")
	if err := os.Mkdir(store, 0o755); err != nil {
		t.Fatal(err)
	}
	reference := "oci://registry.example/plugins/example@" + index.Digest
	output := filepath.Join(root, "evidence.json")
	if err := run(t.Context(), []string{"check", "--store", store, "--checker", checker, "--artifact", reference, "--oci-layout", layout, "--report", output}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var observed []compatibility.Evidence
	if err = json.Unmarshal(data, &observed); err != nil {
		t.Fatal(err)
	}
	if len(observed) != len(layers) {
		t.Fatalf("checked %d of %d platform layers: %s", len(observed), len(layers), data)
	}
	for i, evidence := range observed {
		if "sha256:"+evidence.ReleaseSHA256 != index.Digest || "sha256:"+evidence.Report.ArtifactSHA256 != layers[i].Digest || evidence.Report.Outcome != "passed" {
			t.Fatalf("observation %d does not bind layer %s to root %s: %+v", i, layers[i].Digest, index.Digest, evidence)
		}
	}
	if err = run(t.Context(), []string{"check", "--store", store, "--checker", checker, "--artifact", checker, "--oci-layout", layout}); err == nil || !strings.Contains(err.Error(), "oci://") {
		t.Fatalf("--oci-layout with a local file: %v", err)
	}
}
