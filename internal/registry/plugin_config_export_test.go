package registry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func readConfigIndex(t *testing.T, dir, id string) configSchemaIndex {
	t.Helper()
	path, ok := strings.CutPrefix(id, configSchemaOrigin)
	if !ok {
		t.Fatalf("unexpected schema origin %q", id)
	}
	var index configSchemaIndex
	if err := readRecord(filepath.Join(dir, filepath.FromSlash(path)), &index); err != nil {
		t.Fatal(err)
	}
	if index.ID != id {
		t.Fatalf("expected %s, got %s", id, index.ID)
	}
	return index
}

func TestConfigSchemasResolveTwoReleasesInOneCompiler(t *testing.T) {
	entry := acceptedFixture(t)
	index := EmptyIndex()
	levels := []json.Number{"9007199254740993", "9007199254740994"}
	for i, level := range levels {
		release := entry
		decl := *entry.Artifact
		release.Artifact = &decl
		release.Submission.Tag = fmt.Sprintf("v%d", i+1)
		release.PublishedAt = release.PublishedAt.Add(time.Duration(i) * time.Hour)
		decl.Metadata = fmt.Appendf(nil, `{
			"description":"Example settings",
			"config_schema":{
				"$id":"https://publisher.example/options",
				"$defs":{"setting":{"$id":"shared/setting","$anchor":"level","const":%s}},
				"$ref":"shared/setting#level"
			},
			"rules":[{"name":"example","category":"correctness","options_schema":{"type":"boolean"}}]
		}`, level)
		index.Entries = append(index.Entries, release)
	}

	dir := t.TempDir()
	if err := Export(index, dir, nil, nil); err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	err := filepath.WalkDir(filepath.Join(dir, "schemas"), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".schema.json") {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		return compiler.AddResource(configSchemaOrigin+filepath.ToSlash(rel), doc)
	})
	if err != nil {
		t.Fatal(err)
	}
	root := readConfigIndex(t, dir, configSchemaOrigin+configSchemaRoot)
	plugin := readConfigIndex(t, dir, root.Defs[entry.Name()].Ref)
	for i, level := range levels {
		tag := index.Entries[i].Submission.Tag
		version := readConfigIndex(t, dir, plugin.Defs[tag].Ref)
		config, err := compiler.Compile(version.ID + "#/$defs/config")
		if err != nil {
			t.Fatal(err)
		}
		if config.Validate(level) != nil || config.Validate(levels[1-i]) == nil {
			t.Fatalf("%s did not enforce its exact integer %s", tag, level)
		}
		rule, err := compiler.Compile(version.ID + "#/$defs/rules/$defs/correctness/$defs/example")
		if err != nil {
			t.Fatal(err)
		}
		if rule.Validate(true) != nil || rule.Validate("filename") == nil {
			t.Fatalf("%s did not expose the declared rule options", tag)
		}
	}

	var catalog configCatalog
	if err := readRecord(filepath.Join(dir, configCatalogPath), &catalog); err != nil {
		t.Fatal(err)
	}
	if len(catalog.Schemas) != 1 || catalog.Schemas[0].URL != plugin.Defs["v2"].Ref ||
		catalog.Schemas[0].Versions["v1"] != plugin.Defs["v1"].Ref {
		t.Fatalf("unexpected schema catalog: %+v", catalog.Schemas)
	}
}

func TestConfigSchemaRecommendationRequiresActiveRelease(t *testing.T) {
	entry := acceptedFixture(t)
	entry.Artifact.Metadata = json.RawMessage(`{"config_schema":{"type":"boolean"}}`)
	for _, state := range []ReleaseState{StatusActive, StatusDeprecated, StatusWithdrawn, StatusRevoked} {
		t.Run(string(state), func(t *testing.T) {
			dir := t.TempDir()
			index := Index{Entries: []Entry{entry}}
			if err := exportConfigSchemas(index, dir, []ReleaseStatus{statusFixture(entry, state)}, io.Discard); err != nil {
				t.Fatal(err)
			}
			var catalog configCatalog
			if err := readRecord(filepath.Join(dir, configCatalogPath), &catalog); err != nil {
				t.Fatal(err)
			}
			if (len(catalog.Schemas) != 0) != (state == StatusActive) {
				t.Fatalf("unexpected recommendation for %s: %v", state, catalog.Schemas)
			}
			root := readConfigIndex(t, dir, configSchemaOrigin+configSchemaRoot)
			plugin := readConfigIndex(t, dir, root.Defs[entry.Name()].Ref)
			if plugin.Defs[entry.Submission.Tag] == nil {
				t.Fatalf("lost the historical schema for %s", state)
			}
		})
	}
}

func TestExportOmitsMalformedHistoricalSchema(t *testing.T) {
	valid := acceptedFixture(t)
	valid.Artifact.Metadata = json.RawMessage(`{"config_schema":{"type":"boolean"}}`)
	bad := valid
	bad.Submission.Tag = "broken"
	bad.Artifact = nil
	bad.Validation = &LegacyValidation{Metadata: json.RawMessage(`{"config_schema":{"type":"boolean"},"descriptor":{"category":"bugs","name":"bad","options_schema":{"$ref":"#/$defs/missing"}}}`)}
	dir := t.TempDir()
	var warnings bytes.Buffer
	if err := exportConfigSchemas(Index{Entries: []Entry{bad, valid}}, dir, nil, &warnings); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(warnings.String(), bad.Name()+"@broken") {
		t.Fatalf("missing diagnostic for omitted schema: %s", &warnings)
	}
	root := readConfigIndex(t, dir, configSchemaOrigin+configSchemaRoot)
	plugin := readConfigIndex(t, dir, root.Defs[valid.Name()].Ref)
	if len(plugin.Defs) != 1 || plugin.Defs[valid.Submission.Tag] == nil {
		t.Fatalf("unexpected published releases: %+v", plugin.Defs)
	}
}

func TestExportKeepsLegacySchemaWithNumericDescription(t *testing.T) {
	entry := acceptedFixture(t)
	decl := entry.Artifact
	metadata := json.RawMessage(`{"name":"Historical plugin","description":7,"config_schema":{"type":"boolean"}}`)
	entry.Artifact = nil
	entry.RecordVersion = 0
	entry.Validation = &LegacyValidation{
		Kind: decl.Kind, PluginID: decl.PluginID, PluginVersion: decl.PluginVersion,
		Repository: decl.Repository, Contract: decl.Contract, Metadata: metadata,
		Rules: []string{"example"}, Checks: []string{"host-abi"}, HostCommit: strings.Repeat("a", 40), PolicyVersion: "1",
	}
	index := EmptyIndex()
	if err := index.Add(entry); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := Export(index, dir, nil, nil); err != nil {
		t.Fatal(err)
	}
	var catalog configCatalog
	if err := readRecord(filepath.Join(dir, configCatalogPath), &catalog); err != nil {
		t.Fatal(err)
	}
	if len(catalog.Schemas) != 1 || catalog.Schemas[0].Description != "" {
		t.Fatalf("expected the plugin with an empty description, got %+v", catalog.Schemas)
	}
	version := readConfigIndex(t, dir, catalog.Schemas[0].URL)
	if version.Defs["config"] == nil {
		t.Fatalf("the catalog lost the valid plugin settings: %+v", version)
	}
}
