package registry

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStoreGatesNewSettingsAndLoadsHistoricalRecords(t *testing.T) {
	entry := acceptedFixture(t)
	store := Store{Directory: filepath.Join(t.TempDir(), "plugins")}
	candidate := Index{SchemaVersion: 1, Entries: []Entry{entry}}
	entry.Artifact.Metadata = append(bytes.TrimSuffix(entry.Artifact.Metadata, []byte("}")), []byte(`,"config_schema":{"type":99}}`)...)
	if err := store.Merge(candidate); err == nil || !strings.Contains(err.Error(), "config_schema") {
		t.Fatalf("invalid candidate merge = %v", err)
	}
	loaded, err := store.Load()
	if err != nil || len(loaded.Entries) != 0 {
		t.Fatalf("failed merge changed store: %v, %v", loaded, err)
	}

	// Recreate an older publication that predated schema validation.
	if err := os.MkdirAll(store.Directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := store.createPlugin(filepath.Join(store.Directory, entry.PluginKey()), entry, nil); err != nil {
		t.Fatal(err)
	}
	if err := store.Merge(candidate); err != nil {
		t.Fatalf("idempotent merge of an immutable historical entry: %v", err)
	}
}
