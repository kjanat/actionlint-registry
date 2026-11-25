package registry

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"registry.actionlint.kjanat.dev/internal/artifact"
	"registry.actionlint.kjanat.dev/internal/compatibility"
)

const MaxCompatibilityTargets = 16

var hostRevisionPattern = regexp.MustCompile("^[a-f0-9]{12}([a-f0-9]{28})?$")

type CompatibilityPlan struct {
	SchemaVersion int                   `json:"schema_version"`
	CheckerSHA256 string                `json:"checker_sha256"`
	HostRevision  string                `json:"host_revision"`
	Targets       []CompatibilityTarget `json:"targets"`
	Unavailable   []CompatibilityTarget `json:"unavailable,omitempty"`
}

type CompatibilityTarget struct {
	Plugin        string   `json:"plugin"`
	Version       string   `json:"version"`
	SHA256        string   `json:"sha256"`
	PrimaryLayers []string `json:"primary_layers,omitempty"`
}

func (plan CompatibilityPlan) Validate() error {
	if plan.SchemaVersion != 1 || !digestPattern.MatchString(plan.CheckerSHA256) || !hostRevisionPattern.MatchString(plan.HostRevision) {
		return errors.New("invalid compatibility plan version, checker digest or host revision")
	}
	if plan.Targets == nil || len(plan.Targets)+len(plan.Unavailable) > MaxCompatibilityTargets {
		return errors.New("invalid compatibility target count")
	}
	seen := make(map[string]bool)
	for _, target := range plan.Unavailable {
		if len(target.PrimaryLayers) != 0 {
			return errors.New("unavailable release has planned layers")
		}
	}
	for _, target := range slices.Concat(plan.Targets, plan.Unavailable) {
		if target.Plugin == "" || !namePattern.MatchString(target.Version) || !digestPattern.MatchString(target.SHA256) || seen[target.SHA256] {
			return errors.New("invalid or repeated compatibility target")
		}
		if len(target.PrimaryLayers) > 128 {
			return errors.New("too many OCI layer digests in plan")
		}
		previous := ""
		for _, layer := range target.PrimaryLayers {
			if !digestPattern.MatchString(layer) || layer <= previous || layer == target.SHA256 {
				return errors.New("invalid OCI layer digest in plan")
			}
			previous = layer
		}
		seen[target.SHA256] = true
	}
	return nil
}

func PlanCompatibility(ctx context.Context, index Index, statuses []ReleaseStatus, stored []compatibility.Evidence, checkerSHA256, hostRevision string, limit, offset int, walk OCIWalker, warnings io.Writer) (CompatibilityPlan, error) {
	plan := CompatibilityPlan{SchemaVersion: 1, CheckerSHA256: checkerSHA256, HostRevision: hostRevision, Targets: []CompatibilityTarget{}}
	if err := plan.Validate(); err != nil {
		return plan, err
	}
	if limit < 1 || limit > MaxCompatibilityTargets || offset < 0 {
		return plan, fmt.Errorf("compatibility limit must be 1 to %d and offset must be nonnegative", MaxCompatibilityTargets)
	}
	covered := coveredArtifacts(stored, checkerSHA256, hostRevision)
	var missing []Entry
	coveredLayers := func(digest string, layers []string) bool {
		for _, layer := range layers {
			if !covered[artifactBinding{digest, layer}] {
				return false
			}
		}
		return len(layers) > 0
	}
	for _, entry := range index.Entries {
		if !eligibleCompatibility(entry, statuses) {
			continue
		}
		digest := entry.Submission.Digest()
		done := covered[artifactBinding{digest, digest}]
		if entry.Submission.IsOCI() {
			done = coveredLayers(digest, entry.OCIPrimaryLayers)
		}
		if !done {
			missing = append(missing, entry)
		}
	}
	slices.SortFunc(missing, func(a, b Entry) int {
		return cmp.Or(cmp.Compare(a.Name(), b.Name()), cmp.Compare(a.Submission.Tag, b.Submission.Tag))
	})
	seen := make(map[string]bool)
	missing = slices.DeleteFunc(missing, func(entry Entry) bool {
		digest := entry.Submission.Digest()
		duplicate := seen[digest]
		seen[digest] = true
		return duplicate
	})
	if len(missing) == 0 {
		return plan, nil
	}
	offset %= len(missing)
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	for i := range min(limit, len(missing)) {
		entry := missing[(offset+i)%len(missing)]
		target := CompatibilityTarget{Plugin: entry.Name(), Version: entry.Submission.Tag, SHA256: entry.Submission.Digest()}
		if entry.Submission.IsOCI() && len(entry.OCIPrimaryLayers) == 0 {
			reference := entry.Submission.Artifact.Reference()
			// These older records omit the layer list. Recover it from the digest-pinned graph.
			_, err := walk(ctx, reference, func(digest, _ string, _ []byte) error {
				target.PrimaryLayers = append(target.PrimaryLayers, strings.TrimPrefix(digest, "sha256:"))
				return nil
			})
			if err != nil {
				target.PrimaryLayers = nil
				plan.Unavailable = append(plan.Unavailable, target)
				if _, warnErr := fmt.Fprintf(warnings, "Cannot plan %s@%s: %v\n", target.Plugin, target.Version, err); warnErr != nil {
					return plan, warnErr
				}
				continue
			}
			slices.Sort(target.PrimaryLayers)
			target.PrimaryLayers = slices.Compact(target.PrimaryLayers)
			if len(target.PrimaryLayers) == 0 {
				return plan, fmt.Errorf("no primary layers in %s", reference)
			}
			if coveredLayers(target.SHA256, target.PrimaryLayers) || containsRevokedLayer(target.PrimaryLayers, statuses) {
				continue
			}
		}
		plan.Targets = append(plan.Targets, target)
	}
	return plan, plan.Validate()
}

func eligibleCompatibility(entry Entry, statuses []ReleaseStatus) bool {
	status := StatusFor(entry, statuses)
	return (status == nil || status.Status != StatusRevoked && status.Status != StatusWithdrawn) && !containsRevokedLayer(entry.OCIPrimaryLayers, statuses)
}

func containsRevokedLayer(layers []string, statuses []ReleaseStatus) bool {
	for _, status := range statuses {
		if status.Status == StatusRevoked && slices.Contains(layers, status.SHA256) {
			return true
		}
	}
	return false
}

func CheckAccepted(ctx context.Context, index Index, statuses []ReleaseStatus, stored []compatibility.Evidence, target CompatibilityTarget, checker, checkerSHA256, hostRevision string) ([]compatibility.Evidence, error) {
	entry, err := Find(index, target.Plugin, target.Version)
	if err != nil {
		return nil, err
	}
	var client *http.Client
	if entry.Submission.Provider == "github" {
		client = githubDownloadClient()
	} else {
		client = NewGitLab().client
	}
	return checkAccepted(ctx, entry, statuses, stored, target, checker, checkerSHA256, hostRevision, client, NewOCIInspector().Walk)
}

func checkAccepted(ctx context.Context, entry Entry, statuses []ReleaseStatus, stored []compatibility.Evidence, target CompatibilityTarget, executable, checkerSHA256, hostRevision string, client *http.Client, walk OCIWalker) (observed []compatibility.Evidence, err error) {
	plan := CompatibilityPlan{SchemaVersion: 1, CheckerSHA256: checkerSHA256, HostRevision: hostRevision, Targets: []CompatibilityTarget{target}}
	if err := plan.Validate(); err != nil {
		return nil, err
	}
	if !eligibleCompatibility(entry, statuses) {
		return nil, errors.New("release is withdrawn or a digest is revoked")
	}
	if entry.Name() != target.Plugin || entry.Submission.Digest() != target.SHA256 {
		return nil, errors.New("planned plugin or digest does not match the accepted release")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	dir, err := os.MkdirTemp("", "registry-recheck-")
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(dir)) }()
	checker := filepath.Join(dir, "checker")
	digest, err := snapshotFile(executable, checker, 256<<20, 0o700)
	if err != nil {
		return nil, err
	}
	if digest != checkerSHA256 {
		return nil, errors.New("checker executable does not match the planned SHA-256")
	}
	source := entry.Submission.Artifact.Reference()
	if !entry.Submission.IsOCI() {
		if entry.URL != releaseURL(entry.Submission, entry.RepositoryID) {
			return nil, errors.New("noncanonical URL in accepted release")
		}
		source = filepath.Join(dir, entry.Submission.AssetName())
		if err := downloadAsset(ctx, client, entry.URL, source, entry.Submission.Digest(), -1); err != nil {
			return nil, err
		}
	} else {
		verifiedWalk := walk
		walk = func(ctx context.Context, reference string, handle OCILayer) (artifact.Declaration, error) {
			return verifiedWalk(ctx, reference, func(digest, mediaType string, data []byte) error {
				if containsRevokedLayer([]string{strings.TrimPrefix(digest, "sha256:")}, statuses) {
					return errors.New("OCI release contains a revoked layer")
				}
				return handle(digest, mediaType, data)
			})
		}
	}
	observed, err = CheckCompatibility(ctx, checker, source, entry, releaseRunnerAsOf(stored, target.SHA256), walk)
	if err != nil {
		return nil, err
	}
	want := []string{target.SHA256}
	if entry.Submission.IsOCI() {
		want = entry.OCIPrimaryLayers
		if len(want) == 0 {
			// CheckOCI walks the pinned graph and returns one report per verified layer.
			want = target.PrimaryLayers
		}
	}
	var checked []string
	for _, e := range observed {
		if !reportMatchesPin(e, checkerSHA256, hostRevision) || e.Release() != target.SHA256 {
			return nil, errors.New("report does not match the planned checker, host and release")
		}
		checked = append(checked, e.Report.ArtifactSHA256)
	}
	slices.Sort(checked)
	if len(checked) == 0 || (len(want) > 0 && !slices.Equal(checked, want)) {
		return nil, errors.New("checked artifacts differ from the accepted release")
	}
	return observed, nil
}
