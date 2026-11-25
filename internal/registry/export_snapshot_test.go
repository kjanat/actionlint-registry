package registry

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestExportReplacesOnlyOwnedSnapshot(t *testing.T) {
	output := filepath.Join(t.TempDir(), "export")
	entry := acceptedFixture(t)
	if err := Export(Index{SchemaVersion: 1, Entries: []Entry{entry}}, output, nil, nil); err != nil {
		t.Fatal(err)
	}
	plugin := filepath.Join(output, "plugins", entry.PluginKey())
	local := filepath.Join(plugin, "notes.txt")
	if err := os.WriteFile(local, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Export(EmptyIndex(), output, nil, nil); err == nil {
		t.Fatal("replaced output containing an unmanaged file")
	}
	if contents, err := os.ReadFile(local); err != nil || string(contents) != "keep" {
		t.Fatalf("lost local file: %q, %v", contents, err)
	}
	if err := os.Remove(local); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(output, "404.html"), []byte("site"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(filepath.Join(output, siteFiles), []string{"404.html"}); err != nil {
		t.Fatal(err)
	}
	if err := Export(EmptyIndex(), output, nil, nil); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{plugin, filepath.Join(output, "404.html"), filepath.Join(output, siteFiles)} {
		if _, err := os.Stat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("stale output %s: %v", p, err)
		}
	}
}

func TestFailedExportPreservesPublishedSnapshot(t *testing.T) {
	output := t.TempDir()
	if err := Export(EmptyIndex(), output, nil, nil); err != nil {
		t.Fatal(err)
	}
	want := errors.New("invalid input")
	if err := replaceExport(output, func(staging string) error {
		if err := os.WriteFile(filepath.Join(staging, "index.json"), []byte("partial"), 0o600); err != nil {
			return err
		}
		return want
	}); !errors.Is(err, want) {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(output, "index.json")); err != nil || string(data) == "partial" {
		t.Fatalf("failed build changed the published index: %s, %v", data, err)
	}
}

func TestExportPreservesDestinationPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory mode bits are POSIX permissions")
	}
	output := t.TempDir()
	if err := os.Chmod(output, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := Export(EmptyIndex(), output, nil, nil); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(output)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o750 {
		t.Fatalf("export directory permissions changed to %o", mode)
	}
}
