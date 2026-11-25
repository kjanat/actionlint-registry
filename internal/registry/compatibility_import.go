package registry

import (
	"context"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"

	"registry.actionlint.kjanat.dev/internal/compatibility"
)

func ReadCompatibilityPlan(path string) (CompatibilityPlan, error) {
	var plan CompatibilityPlan
	if err := readRecord(path, &plan); err != nil {
		return plan, err
	}
	return plan, plan.Validate()
}

func reportMatchesPin(e compatibility.Evidence, checkerSHA256, hostRevision string) bool {
	return e.CheckerSHA256 == checkerSHA256 && e.Report.Host == (compatibility.Host{Name: "actionlint", Revision: hostRevision}) &&
		e.Report.SchemaVersion == compatibility.ProtocolVersion && e.Report.Policy == "actionlint-smoke/1"
}

type artifactBinding struct{ release, artifact string }

func coveredArtifacts(stored []compatibility.Evidence, checkerSHA256, hostRevision string) map[artifactBinding]bool {
	covered := make(map[artifactBinding]bool)
	for _, e := range stored {
		if reportMatchesPin(e, checkerSHA256, hostRevision) {
			covered[artifactBinding{e.Release(), e.Report.ArtifactSHA256}] = true
		}
	}
	return covered
}

type CompatibilityImport struct {
	CheckerSHA256       string
	HostRevision        string
	Statuses            []ReleaseStatus
	PrimaryLayerDigests func(context.Context, string) ([]string, error)
	Warnings            io.Writer
}

// ImportCompatibility reads one report array or empty .unavailable file per
// planned release. Only the publisher chooses the checker, host and destination.
func (store EvidenceStore) ImportCompatibility(ctx context.Context, index Index, plan CompatibilityPlan, directory string, publication CompatibilityImport) (err error) {
	if err := plan.Validate(); err != nil {
		return err
	}
	if plan.CheckerSHA256 != publication.CheckerSHA256 || plan.HostRevision != publication.HostRevision {
		return errors.New("compatibility plan differs from the pinned checker or host")
	}
	files, err := compatibilityResultFiles(directory, len(plan.Targets))
	if err != nil {
		return err
	}
	stored, err := store.Load(index)
	if err != nil {
		return err
	}
	covered := coveredArtifacts(stored, publication.CheckerSHA256, publication.HostRevision)
	lookup, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	var writes mergeWrites
	defer func() {
		if err != nil {
			err = errors.Join(err, writes.rollback())
		}
	}()
	for _, target := range plan.Targets {
		if err := ctx.Err(); err != nil {
			return err
		}
		entry, err := Find(index, target.Plugin, target.Version)
		if err != nil {
			return err
		}
		layers, err := target.expectedArtifacts(entry)
		if err != nil {
			return err
		}
		if f, ok := files[target.SHA256+".unavailable"]; ok && f.Size() == 0 {
			continue
		}
		name := target.SHA256 + ".json"
		f, ok := files[name]
		if !ok {
			return fmt.Errorf("missing report or empty .unavailable file for %s@%s", target.Plugin, target.Version)
		}
		if !eligibleCompatibility(entry, publication.Statuses) || containsRevokedLayer(target.PrimaryLayers, publication.Statuses) {
			continue
		}
		observations, err := readReleaseReports(filepath.Join(directory, name), f.Size(), layers, target, plan)
		if err != nil {
			return fmt.Errorf("%s@%s: %w", target.Plugin, target.Version, err)
		}
		for _, e := range observations {
			if err := validateEvidence(index, e); err != nil {
				return err
			}
		}
		if entry.Submission.IsOCI() && len(entry.OCIPrimaryLayers) == 0 {
			// Old accepted records have no layer digests. Verify the plan's inventory
			// against the approved manifest before publishing any layer reports.
			actual, err := publication.PrimaryLayerDigests(lookup, entry.Submission.Artifact.Reference())
			if err != nil {
				if ctx.Err() != nil || FailureDisposition(err) == "rejected" {
					return fmt.Errorf("verify OCI layers for %s@%s: %w", target.Plugin, target.Version, err)
				}
				if _, warnErr := fmt.Fprintf(publication.Warnings, "Deferring %s@%s: cannot verify OCI layers: %v\n", target.Plugin, target.Version, err); warnErr != nil {
					return warnErr
				}
				continue
			}
			if !slices.Equal(actual, layers) {
				return fmt.Errorf("planned layers differ from the accepted OCI manifest for %s@%s", target.Plugin, target.Version)
			}
		}
		// A different run can finish the same release between planning and publication.
		missing := slices.DeleteFunc(observations, func(e compatibility.Evidence) bool {
			return covered[artifactBinding{e.Release(), e.Report.ArtifactSHA256}]
		})
		if len(missing) == 0 {
			continue
		}
		if baseline := releaseRunnerAsOf(stored, target.SHA256); baseline != "" && baseline != missing[0].Report.RunnerAsOf {
			if _, err := fmt.Fprintf(publication.Warnings, "Deferring %s@%s: runner assessment date is now %s (checked %s)\n", target.Plugin, target.Version, baseline, missing[0].Report.RunnerAsOf); err != nil {
				return err
			}
			continue
		}
		for _, e := range missing {
			if err := store.write(e, &writes); err != nil {
				return err
			}
		}
	}
	return nil
}

func (target CompatibilityTarget) expectedArtifacts(entry Entry) ([]string, error) {
	if entry.Name() != target.Plugin || entry.Submission.Digest() != target.SHA256 {
		return nil, fmt.Errorf("plan does not match the accepted release %s@%s", target.Plugin, target.Version)
	}
	layers := []string{target.SHA256}
	if entry.Submission.IsOCI() {
		layers = entry.OCIPrimaryLayers
		if len(layers) == 0 {
			layers = target.PrimaryLayers
		} else if len(target.PrimaryLayers) != 0 && !slices.Equal(layers, target.PrimaryLayers) {
			return nil, fmt.Errorf("plan differs from the accepted OCI layers for %s@%s", target.Plugin, target.Version)
		}
		if len(layers) == 0 {
			return nil, fmt.Errorf("no verified primary layers for %s@%s", target.Plugin, target.Version)
		}
	} else if len(target.PrimaryLayers) != 0 {
		return nil, fmt.Errorf("release asset %s@%s cannot have OCI layers", target.Plugin, target.Version)
	}
	return layers, nil
}

func compatibilityResultFiles(directory string, expected int) (map[string]os.FileInfo, error) {
	if err := safePath(directory); err != nil {
		return nil, err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return nil, err
	}
	entries, err := dir.ReadDir(expected + 1)
	if errors.Is(err, io.EOF) {
		err = nil
	}
	if err := errors.Join(err, dir.Close()); err != nil {
		return nil, err
	}
	if len(entries) != expected {
		return nil, fmt.Errorf("expected %d compatibility result files, found %d", expected, len(entries))
	}
	files := make(map[string]os.FileInfo, expected)
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("compatibility result is not a regular file: %s", entry.Name())
		}
		files[entry.Name()] = info
	}
	return files, nil
}

func readReleaseReports(path string, size int64, layers []string, target CompatibilityTarget, plan CompatibilityPlan) (observations []compatibility.Evidence, err error) {
	limit := int64(len(layers)) * maxRecordBytes
	if size > limit {
		return nil, errors.New("compatibility results exceed the report size limit")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	dec := jsontext.NewDecoder(io.LimitReader(file, limit+1))
	if tok, err := dec.ReadToken(); err != nil || tok.Kind() != '[' {
		return nil, errors.New("expected a JSON array of compatibility reports")
	}
	asOf := ""
	seen := make(map[string]bool, len(layers))
	for range layers {
		raw, err := dec.ReadValue()
		if err != nil {
			return nil, err
		}
		if len(raw) > maxRecordBytes {
			return nil, errors.New("compatibility report exceeds 2 MiB")
		}
		var e compatibility.Evidence
		if err := jsonv2.Unmarshal(raw, &e, jsonv2.RejectUnknownMembers(true)); err != nil {
			return nil, err
		}
		if e.Release() != target.SHA256 || !reportMatchesPin(e, plan.CheckerSHA256, plan.HostRevision) {
			return nil, errors.New("compatibility report names another release, checker, host, policy or protocol")
		}
		if asOf == "" {
			asOf = e.Report.RunnerAsOf
		}
		if e.Report.RunnerAsOf != asOf {
			return nil, fmt.Errorf("compatibility report has a different runner assessment date from %s", asOf)
		}
		digest := e.Report.ArtifactSHA256
		if !slices.Contains(layers, digest) || seen[digest] {
			return nil, fmt.Errorf("unexpected or repeated artifact digest: %s", digest)
		}
		seen[digest] = true
		observations = append(observations, e)
	}
	if tok, err := dec.ReadToken(); err != nil || tok.Kind() != ']' {
		return nil, errors.New("unexpected extra compatibility report")
	}
	if _, err := dec.ReadToken(); !errors.Is(err, io.EOF) {
		return nil, errors.New("unexpected data after compatibility reports")
	}
	return observations, nil
}
