package validation

import (
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestProcessManifestCompatibilityUnsupported(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		data := []byte(`{"schema_version":1,"id":"external","version":"1.0.0","transport":"process","process":{"entry":"must-never-execute"}}`)
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
		}
		path := filepath.Join(t.TempDir(), "provider.json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Validate(t.Context(), path); !errors.Is(err, ErrUnsupportedContract) {
			t.Fatal("process became a failed WASM compatibility check", err)
		}
	}
}
