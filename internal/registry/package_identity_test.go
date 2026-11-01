package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"registry.actionlint.kjanat.dev/internal/artifact"
)

func packageFixture(t *testing.T, old Entry, id, tag, asset string) Entry {
	t.Helper()
	entry := changedArtifactFixture(t, old, tag, "core", asset)
	entry.IdentityVersion = 2
	entry.Artifact.PluginID = id
	entry.Artifact.Metadata = bytes.Replace(entry.Artifact.Metadata, []byte(`"id":"example"`), []byte(`"id":"`+id+`"`), 1)
	return entry
}

type packageProvider struct {
	entry Entry
	body  []byte
}

func (p packageProvider) ResolveRelease(context.Context, Submission) (Release, error) {
	return Release{Entry: p.entry}, nil
}

func (p packageProvider) DownloadRelease(_ context.Context, _ Submission, _ Release, path string) error {
	if len(p.body) == 0 {
		return nil
	}
	return os.WriteFile(path, p.body, 0o600)
}

func TestMonorepoPackageAdmissionAndStorage(t *testing.T) {
	legacy := acceptedFixture(t)
	index := EmptyIndex()
	if err := index.Add(legacy); err != nil {
		t.Fatal(err)
	}
	first := packageFixture(t, legacy, "github.com/publisher/plugin/tools/first", "v1.0.0", "first.wasm")
	second := packageFixture(t, legacy, "github.com/publisher/plugin/tools/second", "v1.0.0", "second.wasm")
	for _, candidate := range []Entry{first, second} {
		service := Service{Providers: map[string]ReleaseProvider{"github": packageProvider{entry: candidate}}, Inspect: func(context.Context, string) (artifact.Declaration, error) {
			return *candidate.Artifact, nil
		}}
		admitted, err := service.Admit(t.Context(), &index, candidate.Receipt)
		if err != nil || admitted.IdentityVersion != 2 || admitted.Name() != candidate.PluginID() {
			t.Fatalf("package admission: %+v, %v", admitted, err)
		}
	}
	if first.PluginKey() == second.PluginKey() || first.PluginKey() == legacy.PluginKey() || legacy.PluginKey() != legacy.Receipt.PluginKey() {
		t.Fatal("package keys alias or historical key changed")
	}
	store := Store{Directory: filepath.Join(t.TempDir(), "plugins")}
	if err := store.Merge(index); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil || len(loaded.Entries) != 3 {
		t.Fatalf("store: %+v, %v", loaded, err)
	}
	output := t.TempDir()
	aliases := Aliases{SchemaVersion: 1, Aliases: map[string]AliasTarget{"first": {Repository: first.Name()}}}
	if err := Export(loaded, output, nil, &aliases); err != nil {
		t.Fatal(err)
	}
	var catalogue Catalog
	if err := readRecord(filepath.Join(output, "index.json"), &catalogue); err != nil || len(catalogue.Plugins) != 3 {
		t.Fatalf("catalogue: %+v, %v", catalogue, err)
	}
	for _, entry := range []Entry{legacy, first, second} {
		resolved, err := Find(loaded, entry.Name(), "v1.0.0")
		if err != nil || resolved.PluginID() != entry.PluginID() || resolved.Submission.Asset != entry.Submission.Asset {
			t.Fatalf("distinct selection failed: %+v, %v", resolved, err)
		}
		var manifest PluginManifest
		if err := readRecord(filepath.Join(output, "plugins", entry.PluginKey(), "index.json"), &manifest); err != nil || manifest.Plugin != pluginFor(entry) || len(manifest.Versions) != 1 {
			t.Fatalf("manifest: %+v, %v", manifest, err)
		}
	}
	packages := Index{SchemaVersion: 1, Entries: []Entry{first, second}}
	if _, err := Find(packages, legacy.Name(), "v1.0.0"); err == nil {
		t.Fatal("repository-only selector silently chose a package")
	}
}

func TestPackageIdentityRejectsRebindingAndAliasing(t *testing.T) {
	legacy := acceptedFixture(t)
	first := packageFixture(t, legacy, "github.com/publisher/plugin/tools/first", "v1.0.0", "first.wasm")
	for name, mutate := range map[string]func(*Entry){
		"repository-ID":    func(e *Entry) { e.RepositoryID++; e.Receipt.Identity.RepositoryID = "11" },
		"owner":            func(e *Entry) { e.OwnerID++; e.Receipt.Identity.OwnerID = "6" },
		"identity-version": func(e *Entry) { e.IdentityVersion = 0 },
		"foreign-package": func(e *Entry) {
			e.Artifact.PluginID = "github.com/attacker/plugin/first"
			e.Artifact.Metadata = bytes.ReplaceAll(e.Artifact.Metadata, []byte(first.PluginID()), []byte(e.Artifact.PluginID))
		},
		"case-collision": func(e *Entry) {
			e.Artifact.PluginID = strings.ToUpper(first.PluginID())
			e.Artifact.Metadata = bytes.ReplaceAll(e.Artifact.Metadata, []byte(first.PluginID()), []byte(e.Artifact.PluginID))
		},
		"immutable-version": func(e *Entry) {
			e.Submission.Asset = "replacement.wasm"
			e.Receipt.Submission = e.Submission
			e.URL = releaseURL(e.Submission, e.RepositoryID)
		},
	} {
		t.Run(name, func(t *testing.T) {
			index := EmptyIndex()
			if err := index.Add(first); err != nil {
				t.Fatal(err)
			}
			changed := first
			declaration := *first.Artifact
			changed.Artifact = &declaration
			mutate(&changed)
			if err := index.Add(changed); err == nil || len(index.Entries) != 1 {
				t.Fatalf("accepted identity mutation: %v", err)
			}
		})
	}
}

func TestQualifiedHistoricalIdentityKeepsRepositorySelector(t *testing.T) {
	legacy := packageFixture(t, acceptedFixture(t), "github.com/publisher/plugin/tools/first", "v1.0.0", "first.wasm")
	legacy.IdentityVersion = 0
	store := Store{Directory: filepath.Join(t.TempDir(), "plugins")}
	if err := store.Merge(Index{SchemaVersion: 1, Entries: []Entry{legacy}}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(store.Directory, legacy.PluginKey(), "plugin.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	next := changedArtifactFixture(t, legacy, "v2.0.0", "core", "first.wasm")
	service := Service{Providers: map[string]ReleaseProvider{"github": packageProvider{entry: next}}, Inspect: func(context.Context, string) (artifact.Declaration, error) { return *next.Artifact, nil }}
	admitted, err := service.Admit(t.Context(), &loaded, next.Receipt)
	if err != nil || admitted.IdentityVersion != 0 || admitted.Name() != legacy.Name() {
		t.Fatalf("legacy migration: %+v, %v", admitted, err)
	}
	if err := store.Merge(loaded); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("historical identity rewritten", err)
	}
	var plugin Plugin
	if err := json.Unmarshal(after, &plugin); err != nil || plugin.SchemaVersion != 1 {
		t.Fatal("historical discriminator changed", err)
	}
}

func TestPackageCandidateAndProcessAdmission(t *testing.T) {
	legacy := acceptedFixture(t)
	first := packageFixture(t, legacy, "github.com/publisher/plugin/first", "v1.0.0", "first.wasm")
	id := "github.com/publisher/plugin/process"
	body := bytes.ReplaceAll(processBody(), []byte(`"id":"example"`), []byte(`"id":"`+id+`"`))
	input := filepath.Join(t.TempDir(), "process.json")
	if err := os.WriteFile(input, body, 0o600); err != nil {
		t.Fatal(err)
	}
	declaration, err := artifact.Inspect(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	entry := legacy
	entry.Artifact = &declaration
	entry.Submission.SchemaVersion, entry.Submission.Kind = 2, "manifest"
	entry.Submission.Artifact, err = ReleaseAsset("process.json", declaration.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	entry.Submission.Asset, entry.Submission.SHA256 = "", ""
	entry.Receipt.Submission = entry.Submission
	entry.URL = releaseURL(entry.Submission, entry.RepositoryID)
	index := EmptyIndex()
	if err := index.Add(first); err != nil {
		t.Fatal(err)
	}
	service := Service{Providers: map[string]ReleaseProvider{"github": packageProvider{entry: entry, body: body}}}
	admitted, err := service.Admit(t.Context(), &index, entry.Receipt)
	if err != nil || admitted.IdentityVersion != 2 || admitted.Name() != id {
		t.Fatalf("process admission: %+v, %v", admitted, err)
	}
	// Registration order must not affect candidate lookup amongst sibling IDs.
	for n, entries := range [][]Entry{{admitted, first}, {first, admitted}, {legacy}} {
		output := filepath.Join(t.TempDir(), fmt.Sprintf("candidate-%d", n))
		if _, err := ExportCandidate(t.Context(), input, output, Index{SchemaVersion: 1, Entries: entries}); err != nil {
			t.Fatal(err)
		}
		var catalog Catalog
		if err := readRecord(filepath.Join(output, "index.json"), &catalog); err != nil {
			t.Fatal(err)
		}
		if len(catalog.Plugins) != 1 || catalog.Plugins[0].Name != id {
			t.Fatalf("candidate selector: %+v", catalog)
		}
	}
	status := statusFixture(admitted, StatusWithdrawn)
	status.Name, status.SHA256 = admitted.Name(), admitted.Submission.Digest()
	store := StatusStore{Directory: filepath.Join(t.TempDir(), "statuses")}
	if err := store.Add(index, status); err != nil {
		t.Fatal(err)
	}
	statuses, err := store.Load(index)
	if err != nil || len(statuses) != 1 || StatusFor(first, statuses) != nil || StatusFor(admitted, statuses) == nil {
		t.Fatal("package status leaked to sibling", err)
	}
}

func TestGitLabPackageCannotShadowRepository(t *testing.T) {
	base := acceptedFixture(t)
	convert := func(e Entry, repository, repositoryID string, numericID int64) Entry {
		declaration := *e.Artifact
		e.Artifact = &declaration
		e.Submission.Provider, e.Submission.Repository = "gitlab", repository
		e.Receipt.Submission = e.Submission
		e.Receipt.Identity.Issuer = "https://gitlab.com"
		e.Receipt.Identity.Repository = repository
		e.Receipt.Identity.RepositoryID = repositoryID
		e.RepositoryID, e.UpstreamImmutable = numericID, false
		e.URL = releaseURL(e.Submission, e.RepositoryID)
		e.Artifact.Repository = "https://gitlab.com/" + repository
		e.Artifact.Metadata = bytes.ReplaceAll(e.Artifact.Metadata, []byte(base.Artifact.Repository), []byte(e.Artifact.Repository))
		return e
	}
	legacy := convert(base, "publisher/plugin", "10", 10)
	pkg := packageFixture(t, legacy, "gitlab.com/publisher/plugin/package", "v1.0.0", "package.wasm")
	pkg.URL = releaseURL(pkg.Submission, pkg.RepositoryID)
	repo := convert(base, "publisher/plugin/package", "11", 11)
	for _, entries := range [][]Entry{{pkg, repo}, {repo, pkg}} {
		index := EmptyIndex()
		if err := index.Add(entries[0]); err != nil {
			t.Fatal(err)
		}
		if err := index.Add(entries[1]); err == nil {
			t.Fatal("package/repository selector collision accepted")
		}
	}
}
