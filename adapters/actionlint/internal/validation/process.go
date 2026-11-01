package validation

import (
	"bufio"
	"bytes"
	"compress/gzip"
	jsonv2 "encoding/json/v2"
	"errors"
	"io"
	"os"
)

// Recognition never launches the process or compiles a transform. This adapter
// predates process compatibility checks and must report that limit explicitly.
func isProcessManifest(path string) (process bool, err error) {
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	reader := bufio.NewReader(io.LimitReader(file, (64<<20)+1))
	header, err := reader.Peek(2)
	if err != nil {
		return false, nil
	}
	var input io.Reader = reader
	if bytes.Equal(header, []byte{31, 139}) {
		compressed, openErr := gzip.NewReader(reader)
		if openErr != nil {
			return false, openErr
		}
		defer func() { err = errors.Join(err, compressed.Close()) }()
		input = compressed
	} else if header[0] == 0 {
		return false, nil
	}
	data, err := io.ReadAll(io.LimitReader(input, (128<<20)+1))
	if err != nil {
		return false, err
	}
	if len(data) > 128<<20 {
		return false, errors.New("expanded artifact exceeds 128 MiB")
	}
	if !bytes.HasPrefix(bytes.TrimSpace(data), []byte("{")) {
		return false, nil
	}
	var manifest struct {
		SchemaVersion int    `json:"schema_version"`
		Transport     string `json:"transport"`
	}
	if err := jsonv2.Unmarshal(data, &manifest); err != nil {
		return false, err
	}
	return manifest.SchemaVersion == 1 && manifest.Transport == "process", nil
}
