package registry

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	jsonv2 "encoding/json/v2"
	"registry.actionlint.kjanat.dev/internal/artifact"
)

// InspectLayout verifies a pinned OCI package in a standard image layout. It
// uses the same graph checks as remote inspection and never creates a client.
func InspectLayout(ctx context.Context, reference, layout string) (artifact.Declaration, error) {
	return inspectLayout(ctx, reference, layout, "")
}

func inspectLayout(ctx context.Context, reference, layout, snapshot string) (result artifact.Declaration, err error) {
	distribution, err := OCIReference(reference)
	if err != nil {
		return artifact.Declaration{}, err
	}
	root, err := os.OpenRoot(layout)
	if err != nil {
		return artifact.Declaration{}, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	marker, err := readLayoutFile(ctx, root, "oci-layout", 4096)
	if err != nil {
		return artifact.Declaration{}, err
	}
	var version struct {
		Version string `json:"imageLayoutVersion"`
	}
	if err := jsonv2.Unmarshal(marker, &version); err != nil || version.Version != "1.0.0" {
		return artifact.Declaration{}, errors.New("OCI layout requires imageLayoutVersion 1.0.0")
	}
	indexBytes, err := readLayoutFile(ctx, root, "index.json", 4<<20)
	if err != nil {
		return artifact.Declaration{}, err
	}
	var index ociDocument
	if err := jsonv2.Unmarshal(indexBytes, &index); err != nil || index.SchemaVersion != 2 || index.MediaType != "" && index.MediaType != ociIndex {
		return artifact.Declaration{}, errors.New("invalid OCI layout index")
	}
	found := false
	var selected ociDescriptor
	for _, entry := range index.Manifests {
		if entry.Digest != "sha256:"+distribution.digest {
			continue
		}
		if err := validateDescriptor(entry); err != nil {
			return artifact.Declaration{}, err
		}
		if found && (entry.MediaType != selected.MediaType || entry.Size != selected.Size) {
			return artifact.Declaration{}, errors.New("OCI layout index disagrees about its pinned root")
		}
		selected = entry
		found = true
	}
	if !found {
		return artifact.Declaration{}, errors.New("pinned OCI root is not registered in the layout index")
	}
	if snapshot != "" {
		if err := os.Mkdir(snapshot, 0o700); err != nil {
			return artifact.Declaration{}, err
		}
	}
	readFile := func(ctx context.Context, digest string, limit int64) ([]byte, error) {
		hex, ok := strings.CutPrefix(digest, "sha256:")
		if !ok || !digestPattern.MatchString(hex) {
			return nil, errors.New("OCI layout requires SHA256 blob names")
		}
		return readLayoutFile(ctx, root, "blobs/sha256/"+hex, limit)
	}
	readManifest := func(ctx context.Context, digest string, limit int64) ([]byte, error) {
		if digest != selected.Digest {
			return readFile(ctx, digest, limit)
		}
		data, err := (ociObjects{}).content(ctx, selected, limit, readFile)
		if err != nil {
			return nil, err
		}
		var document ociDocument
		if err := jsonv2.Unmarshal(data, &document); err != nil || document.MediaType != selected.MediaType {
			return nil, errors.New("OCI layout root media type disagrees with its index")
		}
		return data, nil
	}
	verified := func(digest string, data []byte) error {
		if snapshot != "" {
			return os.WriteFile(filepath.Join(snapshot, strings.TrimPrefix(digest, "sha256:")), data, 0o600)
		}
		return nil
	}
	return inspectOCI(ctx, distribution, ociObjects{manifest: readManifest, blob: readFile, verified: verified})
}

func readLayoutFile(ctx context.Context, root *os.Root, path string, limit int64) (data []byte, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := root.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("OCI layout object must be a regular file within its size limit")
	}
	data, err = io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("OCI layout object exceeds its size limit")
	}
	return data, ctx.Err()
}
