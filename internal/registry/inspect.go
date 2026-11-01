package registry

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"io"
	"os"
	"strings"

	"registry.actionlint.kjanat.dev/internal/artifact"
)

// InspectSource inspects supported distribution bytes or an explicit OCI digest.
func InspectSource(ctx context.Context, source string) (artifact.Declaration, error) {
	if strings.HasPrefix(source, "oci://") {
		return NewOCIInspector().Inspect(ctx, source)
	}
	return artifact.Inspect(ctx, source)
}

// Standalone assets have no blob graph in which digest references can resolve.
func validateStandaloneProcess(path string) (err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(data) > artifact.MaxDownload {
		return reject("process manifest exceeds size limit")
	}
	if bytes.HasPrefix(data, []byte{31, 139}) {
		reader, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return err
		}
		data, err = io.ReadAll(io.LimitReader(reader, artifact.MaxModule+1))
		if closeErr := reader.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
		if err != nil {
			return err
		}
	}
	if len(data) > artifact.MaxModule {
		return reject("expanded process manifest exceeds size limit")
	}
	var manifest struct {
		Artifacts []json.RawMessage `json:"artifacts"`
		Process   struct {
			Config struct {
				Transform *struct {
					Digest string `json:"digest"`
				} `json:"transform"`
			} `json:"config"`
			Output struct {
				Transform *struct {
					Digest string `json:"digest"`
				} `json:"transform"`
			} `json:"output"`
		} `json:"process"`
	}
	if err = jsonv2.Unmarshal(data, &manifest); err != nil {
		return reject("invalid standalone process manifest")
	}
	if len(manifest.Artifacts) > 0 || transformDigest(manifest.Process.Config.Transform) != "" || transformDigest(manifest.Process.Output.Transform) != "" {
		return reject("standalone process manifest requires PATH executable and inline transforms; package digest-addressed companions as OCI")
	}
	return nil
}
