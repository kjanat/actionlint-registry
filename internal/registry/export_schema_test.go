package registry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestExportPublishesRegistrySchema(t *testing.T) {
	output := t.TempDir()
	if err := Export(EmptyIndex(), output, nil, nil); err != nil {
		t.Fatal(err)
	}
	type reference struct {
		Ref string `json:"$ref"`
	}
	type resource struct {
		ID          string               `json:"$id"`
		Definitions map[string]reference `json:"$defs"`
	}
	var bundle struct {
		reference
		Definitions map[string]resource `json:"$defs"`
	}
	data, err := os.ReadFile(filepath.Join(output, "schemas", "registry.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.Ref != "index.schema.json" ||
		bundle.Definitions["index"].Definitions["pluginManifest"].Ref != "manifest.schema.json" ||
		bundle.Definitions["manifest"].Definitions["versionRecord"].Ref != "version.schema.json" {
		t.Fatalf("unexpected schema reference chain: %+v", bundle)
	}
	for _, name := range []string{"index", "manifest", "plugin", "version", "compatibility", "artifact", "receipt", "submission", "distribution", "statuses"} {
		if id := bundle.Definitions[name].ID; id != "https://plugins.actionlint.kjanat.dev/schemas/"+name+".schema.json" {
			t.Errorf("schema %s has ID %q", name, id)
		}
	}
}
