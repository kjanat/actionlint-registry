package registry

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"registry.actionlint.kjanat.dev/internal/artifact"
	"registry.actionlint.kjanat.dev/internal/compatibility"
)

type Inspector func(context.Context, string) (artifact.Declaration, error)

type Failure struct {
	Repository  string `json:"repository"`
	Tag         string `json:"tag,omitempty"`
	Error       string `json:"error"`
	Disposition string `json:"disposition"`
}

type Report struct {
	SchemaVersion int       `json:"schema_version"`
	Mode          string    `json:"mode"`
	SubmissionID  string    `json:"submission_id,omitempty"`
	Accepted      []Entry   `json:"accepted"`
	Rejected      []Failure `json:"rejected"`
	NoCandidates  []string  `json:"no_candidates,omitempty"`
}

type rejection struct{ message string }

func (e *rejection) Error() string { return e.message }

func reject(message string) error { return &rejection{message: message} }

// FailureDisposition defaults unknown, upstream, storage and transport failures
// to retryable. Only evidence that establishes invalid content or identity can
// permanently reject a submission.
func FailureDisposition(err error) string {
	var denied *rejection
	var invalid *artifact.InvalidError
	if errors.As(err, &denied) || errors.As(err, &invalid) {
		return "rejected"
	}
	return "retryable"
}

func NewReport(mode string) Report {
	return Report{SchemaVersion: 1, Mode: mode, Accepted: []Entry{}, Rejected: []Failure{}}
}

// WriteReport keeps accepted records within their storage bound when nested.
// Recovery reads one 2 MiB record plus a 32 KiB report envelope.
func WriteReport(path string, report Report) error {
	return writeJSON(path, report, false)
}

type Service struct {
	Providers  map[string]ReleaseProvider
	Inspect    Inspector
	InspectOCI OCIWalker
	Checker    string
}

// Admission is an accepted entry and, when a checker ran, the evidence it produced.
type Admission struct {
	Entry    Entry
	Evidence []compatibility.Evidence
}

func (service Service) Admit(ctx context.Context, index *Index, receipt Receipt) (Admission, error) {
	if err := receipt.Validate(); err != nil {
		return Admission{}, err
	}
	s := receipt.Submission
	provider, ok := service.Providers[s.Provider]
	if !ok {
		return Admission{}, errors.New("unsupported release provider")
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	release, err := provider.ResolveRelease(ctx, s)
	if err != nil {
		return Admission{}, err
	}
	entry := release.Entry
	entry.Receipt = receipt
	if strconv.FormatInt(entry.RepositoryID, 10) != receipt.Identity.RepositoryID || strconv.FormatInt(entry.OwnerID, 10) != receipt.Identity.OwnerID || entry.Commit != receipt.Identity.Commit {
		return Admission{}, reject("release identity or commit disagrees with OIDC publisher")
	}
	for _, old := range index.Entries {
		if old.Receipt.PluginKey() != receipt.PluginKey() && (old.Submission.Provider != s.Provider || !strings.EqualFold(old.Submission.Repository, s.Repository)) {
			continue
		}
		if old.Receipt.PluginKey() != receipt.PluginKey() || old.OwnerID != entry.OwnerID ||
			old.RepositoryID != entry.RepositoryID || old.Submission.Provider != s.Provider ||
			old.Submission.Repository != s.Repository {
			return Admission{}, reject("registered publisher identity changed")
		}
		if old.Submission == s {
			if old.ReleaseID != entry.ReleaseID || old.AssetID != entry.AssetID || old.Commit != entry.Commit || old.URL != entry.URL {
				return Admission{}, reject("accepted version is immutable")
			}
			return Admission{Entry: old}, nil
		}
	}
	var evidence []compatibility.Evidence
	record := func(observed []compatibility.Evidence) error {
		for _, item := range observed {
			if item.Report.Outcome == "failed" {
				return reject("compatibility check failed: " + item.Report.Detail)
			}
		}
		evidence = observed
		return nil
	}
	declaration, err := func() (result artifact.Declaration, err error) {
		if s.IsOCI() {
			walk := service.InspectOCI
			if walk == nil {
				walk = NewOCIInspector().Walk
			}
			var primaryLayers []string
			inspect := func(ctx context.Context, reference string, check OCILayer) (artifact.Declaration, error) {
				return walk(ctx, reference, func(digest, mediaType string, data []byte) error {
					primaryLayers = append(primaryLayers, strings.TrimPrefix(digest, "sha256:"))
					if check != nil {
						return check(digest, mediaType, data)
					}
					return nil
				})
			}
			if service.Checker == "" {
				result, err = inspect(ctx, s.Artifact.Reference(), nil)
			} else {
				var observed []compatibility.Evidence
				result, observed, err = CheckOCI(ctx, service.Checker, inspect, s.Artifact.Reference(), "")
				if err == nil {
					err = record(observed)
				}
			}
			if err == nil {
				if len(primaryLayers) == 0 {
					return result, errors.New("verified OCI release has no primary layers")
				}
				slices.Sort(primaryLayers)
				entry.OCIPrimaryLayers = slices.Compact(primaryLayers)
			}
			return result, err
		}
		dir, err := os.MkdirTemp("", "actionlint-registry-")
		if err != nil {
			return result, err
		}
		defer func() { err = errors.Join(err, os.RemoveAll(dir)) }()
		path := filepath.Join(dir, s.AssetName())
		if err = provider.DownloadRelease(ctx, s, release, path); err != nil {
			return result, err
		}
		inspect := service.Inspect
		if inspect == nil {
			inspect = artifact.Inspect
		}
		result, err = inspect(ctx, path)
		if err == nil && result.Kind == "manifest" {
			err = validateStandaloneProcess(path)
		}
		if err == nil && service.Checker != "" {
			var observed compatibility.Evidence
			observed, err = CheckArtifact(ctx, service.Checker, path, s.Digest(), "")
			if err == nil {
				err = record([]compatibility.Evidence{observed})
			}
		}
		return result, err
	}()
	if err != nil {
		return Admission{}, fmt.Errorf("plugin inspection: %w", err)
	}
	if declaration.Kind != s.Kind {
		return Admission{}, reject("binary kind disagrees with submission")
	}
	expectedRepository := "https://" + s.Provider + ".com/" + s.Repository
	if !strings.EqualFold(declaration.Repository, expectedRepository) || strings.TrimPrefix(declaration.PluginVersion, "v") != strings.TrimPrefix(s.Tag, "v") {
		return Admission{}, reject("embedded repository or version disagrees with authenticated release")
	}
	entry.RecordVersion = 2
	entry.Artifact = &declaration
	if packageID(declaration.PluginID, s.Provider+".com/"+s.Repository) {
		entry.IdentityVersion = 2
	}
	for _, old := range index.Entries {
		if old.PluginID() == declaration.PluginID && old.Receipt.PluginKey() == receipt.PluginKey() {
			entry.IdentityVersion = old.IdentityVersion
			break
		}
	}
	entry.AcceptedAt = time.Now().UTC()
	if err = index.Add(entry); err != nil {
		return Admission{}, err
	}
	return Admission{Entry: entry, Evidence: evidence}, nil
}
