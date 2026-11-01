package registry

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"registry.actionlint.kjanat.dev/internal/artifact"
)

// Candidate records local package contents without claiming a publisher identity
// or a release. Only explicit filesystem catalogues may contain these records.
type Candidate struct {
	Source   string               `json:"source"`
	Artifact artifact.Declaration `json:"artifact"`
	URL      string               `json:"url"`
}

type CandidateManifest struct {
	Source   string        `json:"source"`
	Name     string        `json:"name"`
	PluginID string        `json:"plugin_id"`
	Versions []VersionLink `json:"versions"`
}

// ExportCandidate inspects a local package or digest-pinned OCI package and
// exports an installable catalogue. It never writes accepted publication records.
func ExportCandidate(ctx context.Context, input, output string, existing Index) (candidate Candidate, err error) {
	return exportCandidate(ctx, input, output, existing, func(ctx context.Context, input, _ string) (artifact.Declaration, error) {
		return InspectSource(ctx, input)
	})
}

// ExportLayoutCandidate snapshots the verified reachable OCI graph into the
// candidate catalogue. Its pinned remote source remains the intended source for
// later publication; testing the snapshot needs no network or registry writes.
func ExportLayoutCandidate(ctx context.Context, reference, layout, output string, existing Index) (Candidate, error) {
	return exportCandidate(ctx, reference, output, existing, func(ctx context.Context, input, staging string) (artifact.Declaration, error) {
		return inspectLayout(ctx, input, layout, filepath.Join(staging, "oci-blobs"))
	})
}

type candidateInspector func(context.Context, string, string) (artifact.Declaration, error)

func exportCandidate(ctx context.Context, input, output string, existing Index, inspect candidateInspector) (candidate Candidate, err error) {
	if err = safePath(output); err != nil {
		return candidate, err
	}
	oci := strings.HasPrefix(input, "oci://")
	var distribution Distribution
	if oci {
		distribution, err = OCIReference(input)
		if err != nil {
			return candidate, err
		}
	}
	parent := filepath.Dir(output)
	if err = os.MkdirAll(parent, 0o700); err != nil {
		return candidate, err
	}
	staging, err := os.MkdirTemp(parent, ".candidate-*")
	if err != nil {
		return candidate, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(staging)) }()
	var declaration artifact.Declaration
	var checksum, extension string
	var snapshot string
	if oci {
		declaration, err = inspect(ctx, input, staging)
		if err != nil {
			return candidate, err
		}
		checksum = distribution.digest
		if declaration.SHA256 != checksum {
			return candidate, errors.New("inspected OCI candidate root digest changed")
		}
	} else {
		extension = ".wasm"
		if strings.HasSuffix(input, ".json") || strings.HasSuffix(input, ".json.gz") {
			extension = ".json"
		}
		if strings.HasSuffix(input, ".gz") {
			extension += ".gz"
		}
		snapshot = filepath.Join(staging, "package"+extension)
		checksum, err = snapshotFile(input, snapshot, MaxArtifactBytes, 0o600)
		if err != nil {
			return candidate, err
		}
		declaration, err = inspect(ctx, snapshot, staging)
		if err != nil {
			return candidate, err
		}
		if declaration.SHA256 != checksum {
			return candidate, errors.New("inspected candidate checksum changed")
		}
	}
	if declaration.Kind == "manifest" && !oci {
		if err = validateStandaloneProcess(snapshot); err != nil {
			return candidate, err
		}
	}
	repositoryName := strings.TrimPrefix(declaration.Repository, "https://")
	name := repositoryName
	provider, repository, ok := strings.Cut(name, ".com/")
	version := "v" + strings.TrimPrefix(declaration.PluginVersion, "v")
	submission := Submission{SchemaVersion: 1, Provider: provider, Repository: repository,
		Tag: version, Asset: "plugin" + extension, SHA256: checksum, Kind: declaration.Kind}
	if oci {
		submission.SchemaVersion, submission.Artifact = 2, distribution
		submission.Asset, submission.SHA256 = "", ""
	} else if declaration.Kind == "manifest" {
		distribution, err := ReleaseAsset(submission.Asset, checksum)
		if err != nil {
			return candidate, err
		}
		submission.SchemaVersion, submission.Artifact = 2, distribution
		submission.Asset, submission.SHA256 = "", ""
	}
	if !ok {
		return candidate, errors.New("candidate repository must use GitHub or GitLab")
	}
	if err = submission.Validate(); err != nil {
		return candidate, err
	}
	qualified := packageID(declaration.PluginID, repositoryName)
	if qualified {
		name = strings.ToLower(declaration.PluginID)
	}
	for _, old := range existing.Entries {
		if old.Submission.Provider != provider || !strings.EqualFold(old.Submission.Repository, repository) {
			continue
		}
		if old.PluginID() != declaration.PluginID {
			if !qualified {
				return candidate, reject("registered plugin identity changed")
			}
			continue
		}
		name = old.Name()
		if old.Submission.Tag == version && old.Submission.Digest() != checksum {
			return candidate, reject("accepted version is immutable; use a new package version")
		}
	}
	for _, old := range existing.Entries {
		if strings.EqualFold(old.Name(), name) && old.PluginID() != declaration.PluginID {
			return candidate, reject("package selector is already registered")
		}
	}
	candidateURL := "artifacts/" + checksum + extension
	if oci {
		candidateURL = distribution.Reference()
	} else {
		if err = os.Mkdir(filepath.Join(staging, "artifacts"), 0o700); err != nil {
			return candidate, err
		}
		if err = os.Rename(snapshot, filepath.Join(staging, filepath.FromSlash(candidateURL))); err != nil {
			return candidate, err
		}
	}
	candidate = Candidate{Source: "candidate", Artifact: declaration, URL: candidateURL}
	manifest := "plugins/" + key(name) + "/index.json"
	record := "versions/" + key(version) + ".json"
	if err = WriteJSON(filepath.Join(staging, filepath.FromSlash(strings.TrimSuffix(manifest, "index.json")+record)), candidate); err != nil {
		return candidate, err
	}
	if err = WriteJSON(filepath.Join(staging, filepath.FromSlash(manifest)), CandidateManifest{
		Source: "candidate", Name: name, PluginID: declaration.PluginID,
		Versions: []VersionLink{{Version: version, Record: record, Compatibility: []CompatibilityLink{}}},
	}); err != nil {
		return candidate, err
	}
	if err = writeCatalog(staging, Catalog{SchemaVersion: 1, Source: "candidate", Plugins: []CatalogPlugin{{Name: name, PluginID: declaration.PluginID, Manifest: manifest}}}); err != nil {
		return candidate, err
	}
	if _, err = os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		return candidate, fmt.Errorf("candidate output must be a new directory: %s", output)
	}
	err = os.Rename(staging, output)
	return candidate, err
}
