package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
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
// of the release's earliest dated evidence, then stores the new observations.
func (store EvidenceStore) Recheck(ctx context.Context, index Index, executable, path string, entry Entry, walk OCIWalker) ([]compatibility.Evidence, error) {
	stored, err := store.Load(index)
	if err != nil {
		return nil, err
	}
	runnerAsOf := releaseRunnerAsOf(stored, entry.Submission.Digest())
	observed, err := CheckCompatibility(ctx, executable, path, entry, runnerAsOf, walk)
	if err != nil {
		return nil, err
	}
	for _, evidence := range observed {
		if err = store.Add(index, evidence); err != nil {
			return nil, err
		}
	}
	return observed, nil
}

func releaseRunnerAsOf(stored []compatibility.Evidence, release string) string {
	runnerAsOf := ""
	var earliest time.Time
	for _, evidence := range stored {
		if evidence.Release() != release || evidence.Report.RunnerAsOf == "" {
			continue
		}
		if runnerAsOf == "" || evidence.ObservedAt.Before(earliest) {
			runnerAsOf, earliest = evidence.Report.RunnerAsOf, evidence.ObservedAt
		}
	}
	return runnerAsOf
}

func acceptedRelease(index Index, evidence compatibility.Evidence) error {
	matched := false
	for _, entry := range index.Entries {
		if entry.Submission.Digest() != evidence.Release() || entry.Submission.IsOCI() != (evidence.ReleaseSHA256 != "") {
			continue
		}
		if len(entry.OCIPrimaryLayers) != 0 {
			if _, found := slices.BinarySearch(entry.OCIPrimaryLayers, evidence.Report.ArtifactSHA256); !found {
				return errors.New("compatibility evidence names a layer outside the verified OCI release")
			}
		}
		matched = true
	}
	if matched {
		return nil
	}
	return errors.New("compatibility evidence has no accepted artifact matching its release binding")
}

func (store EvidenceStore) Add(index Index, evidence compatibility.Evidence) error {
	if err := validateEvidence(index, evidence); err != nil {
		return err
	}
	return store.write(evidence, nil)
}

func validateEvidence(index Index, evidence compatibility.Evidence) error {
	if err := evidence.Validate(); err != nil {
		return err
	}
	return acceptedRelease(index, evidence)
}

func (store EvidenceStore) write(evidence compatibility.Evidence, writes *mergeWrites) error {
	data, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		return err
	}
	if len(data)+1 > maxRecordBytes {
		return errors.New("serialized compatibility record exceeds 2 MiB")
	}
	name, err := evidenceName(evidence)
	if err != nil {
		return err
	}
	path := filepath.Join(store.Directory, evidence.Release(), name)
	if err = safePath(path); err != nil {
		return err
	}
	if err = os.MkdirAll(store.Directory, 0o755); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err = os.Mkdir(dir, 0o755); err == nil {
		writes.record(dir)
	} else if !errors.Is(err, os.ErrExist) {
		return err
	}
	// Reuse the immutable, atomic record writer. An identical report is idempotent.
	if err = writeTrackedJSON(path, evidence, writes); !errors.Is(err, os.ErrExist) {
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

func (store EvidenceStore) addAll(index Index, observations []compatibility.Evidence, writes *mergeWrites) error {
	for _, observation := range observations {
		if err := validateEvidence(index, observation); err != nil {
			return err
		}
	}
	for _, observation := range observations {
		if err := store.write(observation, writes); err != nil {
			return err
		}
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
			if err = acceptedRelease(index, evidence); err != nil {
				return nil, err
			}
			name, err := evidenceName(evidence)
			if err != nil {
				return nil, err
			}
			if name != file.Name() || evidence.Release() != dir.Name() {
				return nil, fmt.Errorf("compatibility record identity mismatch: %s", file.Name())
			}
			result = append(result, evidence)
		}
	}
	return result, nil
}

// MergeCandidate merges admitted records and their compatibility evidence. A
// version the store does not hold yet needs evidence for its digest.
func MergeCandidate(store Store, candidate Index, candidateEvidence []compatibility.Evidence, evidence EvidenceStore) error {
	return store.merge(candidate, func(current, merged Index, writes *mergeWrites) error {
		for _, entry := range candidate.Entries {
			if slices.ContainsFunc(current.Entries, func(old Entry) bool { return old.Submission == entry.Submission }) {
				continue
			}
			if err := requireCandidateEvidence(entry, candidateEvidence); err != nil {
				return err
			}
		}
		return evidence.addAll(merged, candidateEvidence, writes)
	})
}

func requireCandidateEvidence(entry Entry, observations []compatibility.Evidence) error {
	release := entry.Submission.Digest()
	identity := entry.Name() + "@" + entry.Submission.Tag
	layers := entry.OCIPrimaryLayers
	if entry.Submission.IsOCI() && len(layers) == 0 {
		return reject(identity + " has no verified OCI primary layers")
	}
	checked := make(map[string]bool)
	for _, observation := range observations {
		if observation.Release() != release {
			continue
		}
		if observation.Report.Outcome == "failed" {
			return reject(identity + " has failed compatibility evidence")
		}
		if entry.Submission.IsOCI() && observation.ReleaseSHA256 == "" {
			return reject(identity + " has OCI evidence without a checked layer")
		}
		checked[observation.Report.ArtifactSHA256] = true
	}
	if len(checked) == 0 {
		return reject(identity + " has no compatibility evidence")
	}
	for _, layer := range layers {
		if !checked[layer] {
			return reject(identity + " has no compatibility evidence for OCI layer " + layer)
		}
	}
	return nil
}

// MergeAdmission writes any checker evidence before accepting the admission.
func (store Store) MergeAdmission(candidate Index, observations []compatibility.Evidence, evidence EvidenceStore) error {
	return store.merge(candidate, func(_, merged Index, writes *mergeWrites) error {
		return evidence.addAll(merged, observations, writes)
	})
}
