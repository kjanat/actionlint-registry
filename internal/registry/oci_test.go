package registry

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"registry.actionlint.kjanat.dev/internal/artifact"
	"registry.actionlint.kjanat.dev/internal/compatibility"
)

func processBody() []byte {
	return []byte(`{"schema_version":1,"id":"example","version":"1.0.0","transport":"process","process":{"entry":"example","output":{"transform":{"language":"jq","inline":"."}}},"metadata":{"metadata_version":1,"transport":"process","id":"example","name":"Example","description":"A plugin","license":"MIT","repository":"https://github.com/publisher/plugin","plugin_version":"1.0.0"}}`)
}

func descriptor(media string, data []byte) ociDescriptor {
	sum := sha256.Sum256(data)
	return ociDescriptor{MediaType: media, Digest: "sha256:" + hex.EncodeToString(sum[:]), Size: int64(len(data))}
}

func ociFixture(t *testing.T, variants ...[]byte) (*OCIInspector, string, map[string][]byte) {
	t.Helper()
	objects := map[string][]byte{}
	config := []byte("{}")
	configDescriptor := descriptor("application/vnd.oci.empty.v1+json", config)
	objects["/v2/plugins/example/blobs/"+configDescriptor.Digest] = config
	var manifests []ociDescriptor
	for _, primary := range variants {
		media := ociProcess
		if bytes.HasPrefix(primary, []byte("\x00asm")) {
			media = ociWASM
		}
		primaryDescriptor := descriptor(media, primary)
		objects["/v2/plugins/example/blobs/"+primaryDescriptor.Digest] = primary
		data, err := json.Marshal(ociDocument{SchemaVersion: 2, MediaType: ociManifest, Config: &configDescriptor, Layers: []ociDescriptor{primaryDescriptor}})
		if err != nil {
			t.Fatal(err)
		}
		manifest := descriptor(ociManifest, data)
		objects["/v2/plugins/example/manifests/"+manifest.Digest] = data
		manifests = append(manifests, manifest)
	}
	root := manifests[0]
	if len(manifests) > 1 {
		data, err := json.Marshal(ociDocument{SchemaVersion: 2, MediaType: ociIndex, Manifests: manifests})
		if err != nil {
			t.Fatal(err)
		}
		root = descriptor(ociIndex, data)
		objects["/v2/plugins/example/manifests/"+root.Digest] = data
	}
	inspector := &OCIInspector{client: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme != "https" || r.URL.Host != "registry.example" || r.Header.Get("Authorization") != "" {
			return nil, errors.New("unexpected OCI endpoint or credential")
		}
		data, found := objects[r.URL.Path]
		if !found {
			return nil, errors.New("missing OCI fixture " + r.URL.Path)
		}
		return response(r, string(data)), nil
	})}}
	return inspector, "oci://registry.example/plugins/example@" + root.Digest, objects
}

func TestOCIProcessRootDigestAndVariants(t *testing.T) {
	inspector, reference, objects := ociFixture(t, processBody(), processBody())
	declaration, err := inspector.Inspect(t.Context(), reference)
	if err != nil {
		t.Fatal(err)
	}
	if declaration.Kind != "manifest" || declaration.Contract != "process/1" || !strings.HasSuffix(reference, "sha256:"+declaration.SHA256) {
		t.Fatalf("wrong root declaration %+v", declaration)
	}
	for path, data := range objects {
		if strings.Contains(path, "/blobs/") && string(data) != "{}" {
			objects[path] = append(data, ' ')
			break
		}
	}
	if _, err := inspector.Inspect(t.Context(), reference); err == nil {
		t.Fatal("mutated OCI layer accepted")
	}
	changed := []byte(strings.ReplaceAll(string(processBody()), `"id":"example"`, `"id":"other"`))
	inspector, reference, _ = ociFixture(t, processBody(), changed)
	if _, err := inspector.Inspect(t.Context(), reference); err == nil {
		t.Fatal("inconsistent platform identities accepted")
	}
}

func TestOCIAnonymousAuthenticationAndRedirectPolicy(t *testing.T) {
	requests := 0
	inspector := &OCIInspector{client: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests++
		if r.URL.Host == "auth.example" {
			if r.Header.Get("Authorization") != "" || r.URL.Query().Get("scope") != "repository:plugins/example:pull" || r.URL.Query().Get("service") != "registry.example" {
				t.Fatal("anonymous auth scope or credentials", r.URL)
			}
			return response(r, `{"token":"anonymous-token"}`), nil
		}
		if r.Header.Get("Authorization") == "" {
			resp := response(r, "")
			resp.StatusCode = http.StatusUnauthorized
			resp.Header.Set("WWW-Authenticate", `bEaReR realm="https://auth.example/token",service="registry.example",scope="repository:other:push"`)
			return resp, nil
		}
		if r.Header.Get("Authorization") != "Bearer anonymous-token" {
			t.Fatal("unexpected auth token")
		}
		return response(r, "verified bytes"), nil
	})}}
	data, err := inspector.fetch(t.Context(), "https://registry.example/v2/plugins/example/blobs/sha256:hash", "plugins/example", 100)
	if err != nil || string(data) != "verified bytes" || requests != 3 {
		t.Fatal("anonymous fetch", string(data), requests, err)
	}
	production := NewOCIInspector()
	for _, target := range []string{"http://registry.example/v2/", "https://127.0.0.1/", "https://[::1]/", "https://user@registry.example/"} {
		if _, err := production.request(t.Context(), target, ""); err == nil {
			t.Fatal("unsafe endpoint accepted", target)
		}
	}
	prior, _ := http.NewRequest(http.MethodGet, "https://registry.example/blobs/", nil)
	redirect, _ := http.NewRequest(http.MethodGet, "https://storage.example/blob", nil)
	redirect.Header.Set("Authorization", "Bearer anonymous-token")
	if err := production.client.CheckRedirect(redirect, []*http.Request{prior}); err != nil || redirect.Header.Get("Authorization") != "" {
		t.Fatal("redirect retained registry bearer", err)
	}
	redirect.URL.Scheme = "http"
	if err := production.client.CheckRedirect(redirect, []*http.Request{prior}); err == nil {
		t.Fatal("insecure redirect accepted")
	}
	redirect.URL.Scheme = "https"
	redirect.URL.Host = "storage.example:5000"
	if err := production.client.CheckRedirect(redirect, []*http.Request{prior}); err != nil {
		t.Fatal("valid public HTTPS port rejected", err)
	}
	redirect.URL.Host = "storage.example:65536"
	if err := production.client.CheckRedirect(redirect, []*http.Request{prior}); err == nil {
		t.Fatal("invalid redirect port accepted")
	}
	if err := production.client.CheckRedirect(redirect, make([]*http.Request, 6)); err == nil {
		t.Fatal("unbounded redirects")
	}
	if _, err := inspector.fetch(t.Context(), "https://registry.example/v2/plugins/example/blobs/sha256:hash", "plugins/example", 2); err == nil {
		t.Fatal("unbounded blob response")
	}
}

func TestOCIGraphReferences(t *testing.T) {
	for name, mutate := range map[string]func([]byte) []byte{
		"missing-executable": func(data []byte) []byte {
			return []byte(strings.TrimSuffix(string(data), "}") + `,"artifacts":[{"filename":"example","platform":"linux/amd64","size":5,"digest":"sha256:` + strings.Repeat("a", 64) + `"}]}`)
		},
		"missing-transform": func(data []byte) []byte {
			return bytes.Replace(data, []byte(`"inline":"."`), []byte(`"digest":"sha256:`+strings.Repeat("a", 64)+`"`), 1)
		},
		"identity": func(data []byte) []byte {
			return bytes.Replace(data, []byte(`"id":"example"`), []byte(`"id":"forged"`), 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			inspector, reference, _ := ociFixture(t, mutate(processBody()))
			if _, err := inspector.Inspect(t.Context(), reference); err == nil {
				t.Fatal("invalid process graph accepted")
			}
		})
	}
	if err := validateDescriptor(ociDescriptor{MediaType: ociWASM, Digest: "sha256:" + strings.Repeat("a", 64), Size: 1, URLs: []string{"https://example.com/blob"}}); err == nil {
		t.Fatal("external descriptor URL accepted")
	}
}

func TestOCIProcessExecutableAndTransformLayers(t *testing.T) {
	executable := []byte("engine bytes never executed by admission")
	transform := []byte(".")
	executableDescriptor := descriptor("application/octet-stream", executable)
	transformDescriptor := descriptor("application/vnd.actionlint.transform.v1+jq", transform)
	primary := strings.Replace(string(processBody()), `"inline":"."`, `"digest":"`+transformDescriptor.Digest+`"`, 1)
	declared, err := json.Marshal(struct {
		Platform string `json:"platform"`
		Filename string `json:"filename"`
		Digest   string `json:"digest"`
		Size     int64  `json:"size"`
	}{"linux/amd64", "example", executableDescriptor.Digest, executableDescriptor.Size})
	if err != nil {
		t.Fatal(err)
	}
	primary = strings.TrimSuffix(primary, "}") + `,"artifacts":[` + string(declared) + `]}`
	inspector, reference, objects := ociFixture(t, []byte(primary))
	_, rootDigest, _ := strings.Cut(reference, "@")
	var root ociDocument
	if err := json.Unmarshal(objects["/v2/plugins/example/manifests/"+rootDigest], &root); err != nil {
		t.Fatal(err)
	}
	root.Layers = append(root.Layers, executableDescriptor, transformDescriptor)
	data, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	rootDescriptor := descriptor(ociManifest, data)
	objects["/v2/plugins/example/manifests/"+rootDescriptor.Digest] = data
	objects["/v2/plugins/example/blobs/"+executableDescriptor.Digest] = executable
	objects["/v2/plugins/example/blobs/"+transformDescriptor.Digest] = transform
	reference = "oci://registry.example/plugins/example@" + rootDescriptor.Digest
	if result, err := inspector.Inspect(t.Context(), reference); err != nil || result.Kind != "manifest" {
		t.Fatal("valid process blob graph rejected", result, err)
	}
	objects["/v2/plugins/example/blobs/"+transformDescriptor.Digest] = []byte("altered transform")
	if _, err := inspector.Inspect(t.Context(), reference); err == nil {
		t.Fatal("mutated transform accepted")
	}
}

func TestOCIForgeTagIdentityWithoutRelease(t *testing.T) {
	distribution, err := OCIReference("oci://registry.example/plugins/example@sha256:" + strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	for _, forge := range []string{"github", "gitlab"} {
		t.Run(forge, func(t *testing.T) {
			submission := Submission{SchemaVersion: 2, Provider: forge, Repository: "publisher/plugin", Tag: "v1.0.0", Kind: "manifest", Artifact: distribution}
			commit := strings.Repeat("a", 40)
			transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
				switch r.URL.Path {
				case "/repos/publisher/plugin":
					return response(r, `{"id":10,"full_name":"publisher/plugin","private":false,"owner":{"id":5}}`), nil
				case "/repos/publisher/plugin/git/ref/tags/v1.0.0":
					return response(r, `{"ref":"refs/tags/v1.0.0","object":{"type":"commit","sha":"`+commit+`"}}`), nil
				case "/repos/publisher/plugin/commits/refs/tags/v1.0.0":
					return response(r, `{"sha":"`+commit+`","commit":{"committer":{"date":"2026-01-01T00:00:00Z"}}}`), nil
				case "/api/v4/projects/publisher/plugin":
					return response(r, `{"id":10,"path_with_namespace":"publisher/plugin","visibility":"public","namespace":{"id":5}}`), nil
				case "/api/v4/projects/10/repository/tags/v1.0.0":
					return response(r, `{"name":"v1.0.0","commit":{"id":"`+commit+`","committed_date":"2026-01-01T00:00:00Z"}}`), nil
				default:
					t.Error("OCI lookup touched release asset API", r.URL)
					return nil, errors.New("unexpected API")
				}
			})
			var provider ReleaseProvider
			if forge == "github" {
				provider, err = newGitHub("test-token", transport)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				provider = &GitLab{client: &http.Client{Transport: transport}}
			}
			resolved, err := provider.ResolveRelease(t.Context(), submission)
			if err != nil {
				t.Fatal(err)
			}
			if resolved.Entry.Commit != commit || resolved.Entry.RepositoryID != 10 || resolved.Entry.OwnerID != 5 || resolved.Entry.ReleaseID != 0 || resolved.Entry.AssetID != 0 || resolved.Entry.UpstreamImmutable || resolved.Entry.URL != distribution.Reference() {
				t.Fatal("bad OCI forge identity", resolved.Entry)
			}
			receipt := sampleReceipt()
			receipt.Submission = submission
			receipt.Identity.Issuer = issuer(forge)
			service := Service{Providers: map[string]ReleaseProvider{forge: provider}, InspectOCI: func(context.Context, string, OCILayer) (artifact.Declaration, error) {
				t.Fatal("forged identity reached inspection")
				return artifact.Declaration{}, nil
			}}
			for _, mutate := range []func(*Receipt){func(r *Receipt) { r.Identity.RepositoryID = "11" }, func(r *Receipt) { r.Identity.OwnerID = "6" }, func(r *Receipt) { r.Identity.Commit = strings.Repeat("b", 40) }} {
				changed := receipt
				mutate(&changed)
				index := EmptyIndex()
				if _, err := service.Admit(t.Context(), &index, changed); err == nil {
					t.Fatal("OIDC mismatch accepted")
				}
			}
		})
	}
}

type processReleaseProvider struct {
	entry Entry
	data  []byte
}

func (p processReleaseProvider) ResolveRelease(context.Context, Submission) (Release, error) {
	return Release{Entry: p.entry}, nil
}
func (p processReleaseProvider) DownloadRelease(_ context.Context, _ Submission, _ Release, path string) error {
	return os.WriteFile(path, p.data, 0o600)
}

func TestProcessReleaseAssetAdmission(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		t.Run(map[bool]string{false: "json", true: "json.gz"}[compressed], func(t *testing.T) {
			data := processBody()
			name := "plugin.json"
			if compressed {
				var buffer bytes.Buffer
				writer := gzip.NewWriter(&buffer)
				if _, err := writer.Write(data); err != nil {
					t.Fatal(err)
				}
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
				data = buffer.Bytes()
				name += ".gz"
			}
			digest := descriptor(ociProcess, data).Digest
			distribution, err := ReleaseAsset(name, strings.TrimPrefix(digest, "sha256:"))
			if err != nil {
				t.Fatal(err)
			}
			receipt := sampleReceipt()
			receipt.Submission = Submission{SchemaVersion: 2, Provider: "github", Repository: "publisher/plugin", Tag: "v1.0.0", Kind: "manifest", Artifact: distribution}
			entry := Entry{Submission: receipt.Submission, RepositoryID: 10, OwnerID: 5, ReleaseID: 20, AssetID: 30, Commit: receipt.Identity.Commit, PublishedAt: time.Now().UTC(), UpstreamImmutable: true, URL: assetURL(receipt.Submission)}
			service := Service{Providers: map[string]ReleaseProvider{"github": processReleaseProvider{entry: entry, data: data}}}
			index := EmptyIndex()
			admitted, err := admitEntry(service.Admit(t.Context(), &index, receipt))
			if err != nil {
				t.Fatal(err)
			}
			if admitted.Artifact.Kind != "manifest" || admitted.Artifact.SHA256 != receipt.Submission.Digest() {
				t.Fatal("process asset identity lost")
			}
			if _, err := url.Parse(admitted.PinnedURL()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestOCIPublicEndpoints(t *testing.T) {
	for _, value := range []string{"0.0.0.1", "127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.0.1", "::1", "fc00::1", "fec0::1", "::ffff:127.0.0.1", "64:ff9b::a00:1"} {
		if publicAddress(netip.MustParseAddr(value)) {
			t.Fatal("private endpoint accepted", value)
		}
	}
	for _, value := range []string{"1.1.1.1", "2606:4700:4700::1111"} {
		if !publicAddress(netip.MustParseAddr(value)) {
			t.Fatal("public endpoint refused", value)
		}
	}
	if _, err := publicDial(t.Context(), "tcp", "127.0.0.1:443"); err == nil {
		t.Fatal("private connection allowed")
	}
}

type ociReleaseProvider struct{ entry Entry }

func (p ociReleaseProvider) ResolveRelease(context.Context, Submission) (Release, error) {
	return Release{Entry: p.entry}, nil
}
func (p ociReleaseProvider) DownloadRelease(context.Context, Submission, Release, string) error {
	return errors.New("OCI must not download a release asset")
}

func TestOCISharedRepositoryKeepsPackageVersionsImmutable(t *testing.T) {
	index := EmptyIndex()
	admit := func(id, command string) (Entry, error) {
		body := bytes.ReplaceAll(processBody(), []byte(`"id":"example"`), []byte(`"id":"`+id+`"`))
		body = bytes.Replace(body, []byte(`"entry":"example"`), []byte(`"entry":"`+command+`"`), 1)
		inspector, reference, _ := ociFixture(t, body)
		distribution, err := OCIReference(reference)
		if err != nil {
			return Entry{}, err
		}
		receipt := sampleReceipt()
		receipt.Submission = Submission{SchemaVersion: 2, Provider: "github", Repository: "publisher/plugin", Tag: "v1.0.0", Kind: "manifest", Artifact: distribution}
		entry := acceptedFixture(t)
		entry.Submission = receipt.Submission
		entry.ReleaseID, entry.AssetID = 0, 0
		entry.UpstreamImmutable = false
		entry.URL = reference
		service := Service{Providers: map[string]ReleaseProvider{"github": ociReleaseProvider{entry}}, InspectOCI: inspector.Walk}
		return admitEntry(service.Admit(t.Context(), &index, receipt))
	}
	const firstID = "github.com/publisher/plugin/tools/first"
	first, err := admit(firstID, "example")
	if err != nil {
		t.Fatal(err)
	}
	second, err := admit("github.com/publisher/plugin/tools/second", "example")
	if err != nil {
		t.Fatal(err)
	}
	if first.IdentityVersion != 2 || second.IdentityVersion != 2 || first.URL == second.URL || strings.Split(first.URL, "@sha256:")[0] != strings.Split(second.URL, "@sha256:")[0] || len(index.Entries) != 2 {
		t.Fatal("sibling OCI packages did not share a repository and tag", index)
	}
	if _, err := admit(firstID, "replacement"); err == nil || FailureDisposition(err) != "rejected" || !strings.Contains(err.Error(), "immutable") || len(index.Entries) != 2 {
		t.Fatalf("accepted a replacement for an inspected package version: %v", err)
	}
}

func TestOCIAdmissionIdentityAndImmutability(t *testing.T) {
	inspector, reference, _ := ociFixture(t, processBody())
	distribution, err := OCIReference(reference)
	if err != nil {
		t.Fatal(err)
	}
	receipt := sampleReceipt()
	receipt.Submission = Submission{SchemaVersion: 2, Provider: "github", Repository: "publisher/plugin", Tag: "v1.0.0", Kind: "manifest", Artifact: distribution}
	entry := acceptedFixture(t)
	entry.Submission = receipt.Submission
	entry.ReleaseID, entry.AssetID = 0, 0
	entry.UpstreamImmutable = false
	entry.URL = reference
	service := Service{Providers: map[string]ReleaseProvider{"github": ociReleaseProvider{entry}}, InspectOCI: inspector.Walk}
	index := EmptyIndex()
	admitted, err := admitEntry(service.Admit(t.Context(), &index, receipt))
	if err != nil {
		t.Fatal(err)
	}
	if admitted.Artifact.SHA256 != receipt.Submission.Digest() || admitted.PinnedURL() != reference {
		t.Fatal("lost root digest reference")
	}
	snapshot := collectDownloads(t.Context(), index, counterFunc(func(context.Context, Entry) (int64, error) {
		t.Fatal("OCI counted as a forge release asset")
		return 0, nil
	}))
	if snapshot.Releases[0].Status != "unsupported" || snapshot.Releases[0].SHA256 != receipt.Submission.Digest() {
		t.Fatal("OCI metrics lost unsupported/root digest semantics")
	}
	if resolved, err := Resolve(index, "github.com/publisher/plugin", "v1.0.0"); err != nil || resolved != reference {
		t.Fatal("wrong exported resolution", resolved, err)
	}
	store := Store{Directory: filepath.Join(t.TempDir(), "plugins")}
	if err := store.Merge(index); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err != nil {
		t.Fatal(err)
	}
	changed := receipt
	changed.Submission.Artifact, err = OCIReference("oci://registry.example/plugins/example@sha256:" + strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	entry.Submission = changed.Submission
	entry.URL = changed.Submission.Artifact.Reference()
	service.Providers["github"] = ociReleaseProvider{entry}
	if _, err := service.Admit(t.Context(), &index, changed); err == nil {
		t.Fatal("changed accepted root digest")
	}
	entry.Commit = strings.Repeat("b", 40)
	service.Providers["github"] = ociReleaseProvider{entry}
	if _, err := service.Admit(t.Context(), &index, changed); err == nil {
		t.Fatal("OIDC commit mismatch accepted")
	}
}

func TestProcessAssetInspectionAndCandidate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plugin.json")
	if err := os.WriteFile(path, processBody(), 0o600); err != nil {
		t.Fatal(err)
	}
	declaration, err := artifact.Inspect(t.Context(), path)
	if err != nil || declaration.Contract != "process/1" {
		t.Fatal(declaration, err)
	}
	output := filepath.Join(t.TempDir(), "catalogue")
	if _, err := ExportCandidate(t.Context(), path, output, EmptyIndex()); err != nil {
		t.Fatal(err)
	}
	bad := []byte(strings.Replace(string(processBody()), `"inline":"."`, `"digest":"sha256:`+strings.Repeat("a", 64)+`"`, 1))
	if err := os.WriteFile(path, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ExportCandidate(t.Context(), path, filepath.Join(t.TempDir(), "catalogue"), EmptyIndex()); err == nil {
		t.Fatal("unbundled transform accepted")
	}
}

func ociCandidate(t *testing.T) Entry {
	t.Helper()
	inspector, reference, _ := ociFixture(t, processBody())
	distribution, err := OCIReference(reference)
	if err != nil {
		t.Fatal(err)
	}
	receipt := sampleReceipt()
	receipt.Submission = Submission{SchemaVersion: 2, Provider: "github", Repository: "publisher/plugin", Tag: "v1.0.0", Kind: "manifest", Artifact: distribution}
	entry := acceptedFixture(t)
	entry.Submission = receipt.Submission
	entry.ReleaseID, entry.AssetID = 0, 0
	entry.UpstreamImmutable = false
	entry.URL = reference
	service := Service{Providers: map[string]ReleaseProvider{"github": ociReleaseProvider{entry}}, InspectOCI: inspector.Walk}
	index := EmptyIndex()
	admitted, err := admitEntry(service.Admit(t.Context(), &index, receipt))
	if err != nil {
		t.Fatal(err)
	}
	return admitted
}

func layerObservation(entry Entry, layer string) compatibility.Evidence {
	evidence := observation(entry, "passed")
	evidence.Report.ArtifactSHA256, evidence.ReleaseSHA256 = layer, entry.Submission.Digest()
	return evidence
}

func TestMergeCandidateRequiresEvidence(t *testing.T) {
	release := acceptedFixture(t)
	oci := ociCandidate(t)
	for name, test := range map[string]struct {
		entry    Entry
		evidence []compatibility.Evidence
		merged   bool
	}{
		"oci without evidence":         {oci, nil, false},
		"oci with layer evidence":      {oci, []compatibility.Evidence{layerObservation(oci, oci.OCIPrimaryLayers[0])}, true},
		"release without evidence":     {release, nil, false},
		"release with evidence":        {release, []compatibility.Evidence{observation(release, "passed")}, true},
		"release with failed evidence": {release, []compatibility.Evidence{observation(release, "failed")}, false},
	} {
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			store := Store{Directory: filepath.Join(directory, "plugins")}
			evidence := EvidenceStore{Directory: filepath.Join(directory, "compatibility")}
			candidate := EmptyIndex()
			if err := candidate.Add(test.entry); err != nil {
				t.Fatal(err)
			}
			err := MergeCandidate(store, candidate, test.evidence, evidence)
			loaded, loadErr := store.Load()
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			if !test.merged {
				if err == nil || FailureDisposition(err) != "rejected" || len(loaded.Entries) != 0 {
					t.Fatalf("version without evidence merged or retried: %v, %d entries", err, len(loaded.Entries))
				}
				return
			}
			if err != nil || len(loaded.Entries) != 1 {
				t.Fatalf("merge failed: %v, %d entries", err, len(loaded.Entries))
			}
			stored, err := evidence.Load(loaded)
			if err != nil || len(stored) != len(test.evidence) {
				t.Fatalf("merge stored %d evidence records, want %d: %v", len(stored), len(test.evidence), err)
			}
		})
	}
}

const otherPlatformLayer = "other-platform"

func customSection(name, payload string) []byte {
	body := append([]byte{byte(len(name))}, name...)
	body = append(body, payload...)
	section := []byte{0}
	for size := len(body); ; size >>= 7 {
		if size < 128 {
			section = append(section, byte(size))
			break
		}
		section = append(section, byte(size&127)|128)
	}
	return append(section, body...)
}

func componentLayer(platform string) []byte {
	layer := []byte("\x00asm\x0d\x00\x01\x00")
	layer = append(layer, customSection("actionlint.plugin", componentMetadata("oci"))...)
	return append(layer, customSection("registry-test.platform", platform)...)
}

func ociComponentRelease(t *testing.T, layers ...[]byte) (Service, Receipt, *OCIInspector) {
	t.Helper()
	inspector, reference, _ := ociFixture(t, layers...)
	distribution, err := OCIReference(reference)
	if err != nil {
		t.Fatal(err)
	}
	checker, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	receipt := sampleReceipt()
	receipt.Submission = Submission{SchemaVersion: 2, Provider: "github", Repository: "publisher/plugin", Tag: "v1.0.0", Kind: "component", Artifact: distribution}
	entry := acceptedFixture(t)
	entry.Submission = receipt.Submission
	entry.ReleaseID, entry.AssetID = 0, 0
	entry.UpstreamImmutable = false
	entry.URL = reference
	return Service{Providers: map[string]ReleaseProvider{"github": ociReleaseProvider{entry}}, InspectOCI: inspector.Walk, Checker: checker}, receipt, inspector
}

func TestOCIReleaseEvidenceCoversEveryPlatformLayer(t *testing.T) {
	linux, darwin := componentLayer("linux"), componentLayer("darwin")
	service, receipt, inspector := ociComponentRelease(t, linux, darwin)
	index := EmptyIndex()
	admission, err := service.Admit(t.Context(), &index, receipt)
	if err != nil {
		t.Fatal(err)
	}
	layers := []string{descriptor(ociWASM, linux).Digest, descriptor(ociWASM, darwin).Digest}
	wantInventory := slices.Sorted(slices.Values([]string{strings.TrimPrefix(layers[0], "sha256:"), strings.TrimPrefix(layers[1], "sha256:")}))
	if !slices.Equal(admission.Entry.OCIPrimaryLayers, wantInventory) {
		t.Fatalf("primary layers = %v, want %v", admission.Entry.OCIPrimaryLayers, wantInventory)
	}
	if len(admission.Evidence) != 2 {
		t.Fatalf("admission recorded %d observations for 2 platform layers", len(admission.Evidence))
	}
	for i, evidence := range admission.Evidence {
		if evidence.ReleaseSHA256 != receipt.Submission.Digest() || "sha256:"+evidence.Report.ArtifactSHA256 != layers[i] || evidence.Report.Outcome != "passed" {
			t.Fatalf("observation %d does not bind layer %s to release %s: %+v", i, layers[i], receipt.Submission.Digest(), evidence)
		}
	}
	store := EvidenceStore{Directory: filepath.Join(t.TempDir(), "compatibility")}
	for _, evidence := range admission.Evidence {
		if err = store.Add(index, evidence); err != nil {
			t.Fatal(err)
		}
	}
	stored, err := store.Load(index)
	if err != nil || len(stored) != 2 {
		t.Fatalf("stored %d observations: %v", len(stored), err)
	}
	version := exportedVersion(t, index, stored)
	var imports, exports []string
	if err = errors.Join(json.Unmarshal(version["imports"], &imports), json.Unmarshal(version["exports"], &exports)); err != nil || !slices.Equal(imports, []string{"wasi:cli/environment@0.2.0"}) || !slices.Equal(exports, []string{"kjanat:actionlint/analyzer@0.2.0"}) {
		t.Fatalf("agreeing platforms lost their interfaces: %s %s: %v", version["imports"], version["exports"], err)
	}
	var links []CompatibilityLink
	if err = json.Unmarshal(version["compatibility"], &links); err != nil || len(links) != 2 {
		t.Fatalf("compatibility links %s: %v", version["compatibility"], err)
	}

	rechecked, err := store.Recheck(t.Context(), index, service.Checker, admission.Entry.PinnedURL(), admission.Entry, inspector.Walk)
	if err != nil || len(rechecked) != 2 {
		t.Fatalf("recheck observed %d layers: %v", len(rechecked), err)
	}
	if _, err = store.Recheck(t.Context(), index, service.Checker, admission.Entry.PinnedURL()+"x", admission.Entry, inspector.Walk); err == nil {
		t.Fatal("recheck accepted a reference other than the release's")
	}
	unbound := admission.Evidence[0]
	unbound.ReleaseSHA256 = ""
	unbound.Report.ArtifactSHA256 = receipt.Submission.Digest()
	if err = store.Add(index, unbound); err == nil {
		t.Fatal("stored OCI evidence that names no checked layer")
	}
}

func TestOCIPublicationRequiresCompleteLayerEvidence(t *testing.T) {
	service, receipt, _ := ociComponentRelease(t, componentLayer("linux"), componentLayer("darwin"))
	index := EmptyIndex()
	admission, err := service.Admit(t.Context(), &index, receipt)
	if err != nil {
		t.Fatal(err)
	}
	partial := admission.Evidence[:1]
	version := exportedVersion(t, index, partial)
	if version["imports"] != nil || version["exports"] != nil {
		t.Fatal("published interfaces with a missing platform report")
	}
	legacy := Index{SchemaVersion: 1, Entries: slices.Clone(index.Entries)}
	legacy.Entries[0].OCIPrimaryLayers = nil
	version = exportedVersion(t, legacy, admission.Evidence)
	if version["imports"] != nil || version["exports"] != nil {
		t.Fatal("published interfaces without a verified layer inventory")
	}
	unrelated := admission.Evidence[1]
	unrelated.Report.ArtifactSHA256 = strings.Repeat("e", 64)
	failed := admission.Evidence[1]
	failed.Report.Outcome, failed.Report.Detail = "failed", "fixture is incompatible"
	for _, tc := range []struct {
		name         string
		observations []compatibility.Evidence
	}{
		{"missing layer", partial},
		{"unrelated layer substituted", []compatibility.Evidence{partial[0], unrelated}},
		{"unrelated extra layer", append(slices.Clone(admission.Evidence), unrelated)},
		{"failed layer", []compatibility.Evidence{partial[0], failed}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			store := Store{Directory: filepath.Join(root, "plugins")}
			evidence := EvidenceStore{Directory: filepath.Join(root, "compatibility")}
			if err := MergeCandidate(store, index, tc.observations, evidence); err == nil {
				t.Fatal("published OCI candidate with invalid or incomplete evidence")
			}
			if current, err := store.Load(); err != nil || len(current.Entries) != 0 {
				t.Fatalf("release store changed after rejected merge: %+v, %v", current, err)
			}
			if stored, err := evidence.Load(EmptyIndex()); err != nil || len(stored) != 0 {
				t.Fatalf("evidence store changed after rejected merge: %+v, %v", stored, err)
			}
		})
	}
	root := t.TempDir()
	store := Store{Directory: filepath.Join(root, "plugins")}
	evidence := EvidenceStore{Directory: filepath.Join(root, "compatibility")}
	if err := MergeCandidate(store, index, admission.Evidence, evidence); err != nil {
		t.Fatal(err)
	}
	if err := MergeCandidate(store, index, []compatibility.Evidence{failed}, evidence); err != nil {
		t.Fatalf("could not record a failed observation for an accepted release: %v", err)
	}
}

func TestOCIPlatformsDisagreeingOnInterfacesPublishNone(t *testing.T) {
	service, receipt, _ := ociComponentRelease(t, componentLayer("linux"), componentLayer(otherPlatformLayer))
	index := EmptyIndex()
	admission, err := service.Admit(t.Context(), &index, receipt)
	if err != nil {
		t.Fatal(err)
	}
	if len(admission.Evidence) != 2 || slices.Equal(admission.Evidence[0].Report.Exports, admission.Evidence[1].Report.Exports) {
		t.Fatalf("fixture platforms agree: %+v", admission.Evidence)
	}
	version := exportedVersion(t, index, admission.Evidence)
	if _, found := version["imports"]; found {
		t.Fatalf("published imports for disagreeing platforms: %s", version["imports"])
	}
	if _, found := version["exports"]; found {
		t.Fatalf("published exports for disagreeing platforms: %s", version["exports"])
	}
}

func TestReleaseAssetEvidenceCannotNameARelease(t *testing.T) {
	entry := acceptedFixture(t)
	index := EmptyIndex()
	if err := index.Add(entry); err != nil {
		t.Fatal(err)
	}
	evidence := observation(entry, "passed")
	evidence.ReleaseSHA256, evidence.Report.ArtifactSHA256 = entry.Submission.Digest(), strings.Repeat("d", 64)
	if err := (EvidenceStore{Directory: filepath.Join(t.TempDir(), "compatibility")}).Add(index, evidence); err == nil {
		t.Fatal("stored layer evidence for a release asset")
	}
}

func TestOCIPlatformsMustShareMetadata(t *testing.T) {
	header := []byte("\x00asm\x0d\x00\x01\x00")
	layer := func(metadata, platform string) []byte {
		data := append(slices.Clone(header), customSection("actionlint.plugin", metadata)...)
		return append(data, customSection("registry-test.platform", platform)...)
	}
	metadata := componentMetadata("oci")
	reordered := strings.Replace(metadata, `{"metadata_version":1,`, `{`, 1)
	reordered = strings.TrimSuffix(reordered, "}") + `,"metadata_version":1}`
	inspector, reference, _ := ociFixture(t, layer(metadata, "linux"), layer(reordered, "darwin"))
	if _, err := inspector.Inspect(t.Context(), reference); err != nil {
		t.Fatalf("platforms whose metadata differs only in member order were rejected: %v", err)
	}
	inspector, reference, _ = ociFixture(t, layer(metadata, "linux"), layer(componentMetadata("darwin"), "darwin"))
	if _, err := inspector.Inspect(t.Context(), reference); err == nil || FailureDisposition(err) != "rejected" || !strings.Contains(err.Error(), "metadata") {
		t.Fatalf("platforms with different metadata were accepted: %v", err)
	}
}

func TestOCIPlatformWithoutListsPublishesNone(t *testing.T) {
	service, receipt, _ := ociComponentRelease(t, componentLayer("linux"), componentLayer("darwin"))
	index := EmptyIndex()
	admission, err := service.Admit(t.Context(), &index, receipt)
	if err != nil {
		t.Fatal(err)
	}
	unlisted := admission.Evidence[1]
	unlisted.Report.Outcome, unlisted.Report.Detail = "failed", "validate component contract: newer parser rejects this platform"
	unlisted.Report.Imports, unlisted.Report.Exports = nil, nil
	version := exportedVersion(t, index, []compatibility.Evidence{admission.Evidence[0], unlisted})
	if _, found := version["imports"]; found {
		t.Fatalf("published imports although one platform has no lists: %s", version["imports"])
	}
	if _, found := version["exports"]; found {
		t.Fatalf("published exports although one platform has no lists: %s", version["exports"])
	}
}
