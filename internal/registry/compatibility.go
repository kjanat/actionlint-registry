package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"registry.actionlint.kjanat.dev/internal/compatibility"
)

// EvidenceStore appends observations separately from immutable release records.
type EvidenceStore struct{ Directory string }

func evidenceName(e compatibility.Evidence) (string, error) {
	data, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	return key(string(data)) + ".json", nil
}

// Recheck runs the checker on an accepted release with the runner assessment date
// of the release's earliest dated evidence, then stores the new observation.
func (store EvidenceStore) Recheck(ctx context.Context, index Index, executable, path string, entry Entry) (compatibility.Evidence, error) {
	stored, err := store.Load(index)
	if err != nil {
		return compatibility.Evidence{}, err
	}
	runnerAsOf := ""
	var earliest time.Time
	for _, evidence := range stored {
		if evidence.Report.ArtifactSHA256 != entry.Submission.Digest() || evidence.Report.RunnerAsOf == "" {
			continue
		}
		if runnerAsOf == "" || evidence.ObservedAt.Before(earliest) {
			runnerAsOf, earliest = evidence.Report.RunnerAsOf, evidence.ObservedAt
		}
	}
	evidence, err := CheckCompatibility(ctx, executable, path, entry, runnerAsOf)
	if err != nil {
		return evidence, err
	}
	return evidence, store.Add(index, evidence)
}

func (store EvidenceStore) Add(index Index, evidence compatibility.Evidence) error {
	if err := evidence.Validate(); err != nil {
		return err
	}
	found := false
	for _, entry := range index.Entries {
		if entry.Submission.Digest() == evidence.Report.ArtifactSHA256 {
			found = true
		}
	}
	if !found {
		return errors.New("compatibility evidence has no accepted artifact")
	}
	name, err := evidenceName(evidence)
	if err != nil {
		return err
	}
	path := filepath.Join(store.Directory, evidence.Report.ArtifactSHA256, name)
	if err = safePath(path); err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return err
	}
	// Reuse the immutable, atomic record writer. An identical report is idempotent.
	if err = writeImmutableJSON(path, evidence); !errors.Is(err, os.ErrExist) {
		return err
	}
	old, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(old, append(data, '\n')) {
		return errors.New("refusing to replace compatibility evidence")
	}
	return nil
}

func (store EvidenceStore) Load(index Index) ([]compatibility.Evidence, error) {
	result := []compatibility.Evidence{}
	if err := safePath(store.Directory); err != nil {
		return nil, err
	}
	dirs, err := os.ReadDir(store.Directory)
	if errors.Is(err, os.ErrNotExist) {
		return result, nil
	}
	if err != nil {
		return nil, err
	}
	accepted := map[string]bool{}
	for _, entry := range index.Entries {
		accepted[entry.Submission.Digest()] = true
	}
	for _, dir := range dirs {
		if !dir.IsDir() || !digestPattern.MatchString(dir.Name()) || !accepted[dir.Name()] {
			return nil, errors.New("unexpected compatibility artifact directory")
		}
		base := filepath.Join(store.Directory, dir.Name())
		if err = safePath(base); err != nil {
			return nil, err
		}
		files, err := os.ReadDir(base)
		if err != nil {
			return nil, err
		}
		for _, file := range files {
			if file.IsDir() || !strings.HasSuffix(file.Name(), ".json") {
				return nil, errors.New("unexpected compatibility record")
			}
			var evidence compatibility.Evidence
			if err = readRecord(filepath.Join(base, file.Name()), &evidence); err != nil {
				return nil, err
			}
			if err = evidence.Validate(); err != nil {
				return nil, err
			}
			name, err := evidenceName(evidence)
			if err != nil {
				return nil, err
			}
			if name != file.Name() || evidence.Report.ArtifactSHA256 != dir.Name() {
				return nil, fmt.Errorf("compatibility record identity mismatch: %s", file.Name())
			}
			result = append(result, evidence)
		}
	}
	return result, nil
}
