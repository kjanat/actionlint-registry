package registry

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"

	"registry.actionlint.kjanat.dev/internal/compatibility"
)

const batchTestRevision = "0123456789ab"

func TestCompatibilityPlanUsesBoundedRotatingDigestSelection(t *testing.T) {
	entry := acceptedFixture(t)
	index := EmptyIndex()
	for i := 8; i > 0; i-- {
		e := entry
		e.Submission.Tag = fmt.Sprintf("v%d", i)
		e.Submission.SHA256 = key(e.Submission.Tag)
		index.Entries = append(index.Entries, e)
	}
	duplicate := index.Entries[0]
	duplicate.Submission.Tag = "v9"
	index.Entries = append(index.Entries, duplicate)
	checksum := key("checker")
	completed := observation(index.Entries[0], "failed")
	completed.CheckerSHA256 = checksum
	completed.Report.Policy = "actionlint-smoke/1"
	completed.Report.Host = compatibility.Host{Name: "actionlint", Revision: batchTestRevision}
	completed.Report.SchemaVersion = 3
	completed.Report.RunnerAsOf = "2026-10-01"
	old := completed
	old.Report.ArtifactSHA256 = key("v2")
	old.CheckerSHA256 = key("old checker")

	plan, err := PlanCompatibility(t.Context(), index, nil, []compatibility.Evidence{completed, old}, checksum, batchTestRevision, 3, 5, nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	var tags []string
	for _, item := range plan.Targets {
		tags = append(tags, item.Version)
	}
	if !slices.Equal(tags, []string{"v6", "v7", "v1"}) {
		t.Fatalf("planned tags: %v", tags)
	}
	plan, err = PlanCompatibility(t.Context(), index, nil, nil, checksum, batchTestRevision, 16, 0, nil, io.Discard)
	if err != nil || len(plan.Targets) != 8 || plan.Targets[7].Version != "v8" {
		t.Fatalf("repeated artifact planned more than once: %+v, %v", plan, err)
	}
	if _, err := PlanCompatibility(t.Context(), index, nil, nil, checksum, batchTestRevision, 17, 0, nil, io.Discard); err == nil {
		t.Fatal("accepted unbounded plan")
	}
}

func TestCheckAcceptedVerifiedProcessAssetsAndOCI(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	checksum := key(string(binary))
	data := processBody()
	inspector, _, _ := ociFixture(t, data)
	oci := ociCandidate(t)
	plain := acceptedFixture(t)
	distribution, err := ReleaseAsset("provider.json", key(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	plain.Submission.SchemaVersion = 2
	plain.Submission.Artifact = distribution
	plain.Submission.Asset, plain.Submission.SHA256, plain.Submission.Kind = "", "", "manifest"
	plain.URL = releaseURL(plain.Submission, plain.RepositoryID)
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != plain.URL || r.Header.Get("Authorization") != "" {
			t.Fatalf("unexpected public asset request %s", r.URL)
		}
		return response(r, string(data)), nil
	})}
	var legacyReports []compatibility.Evidence
	for _, kind := range []string{"release asset", "OCI", "historical OCI"} {
		t.Run(kind, func(t *testing.T) {
			entry := oci
			switch kind {
			case "release asset":
				entry = plain
			case "historical OCI":
				entry.OCIPrimaryLayers = nil
			}
			index := Index{Entries: []Entry{entry}}
			plan, err := PlanCompatibility(t.Context(), index, nil, nil, checksum, batchTestRevision, 1, 0, inspector.PrimaryLayerDigests, io.Discard)
			if err != nil || len(plan.Targets) != 1 {
				t.Fatalf("plan: %+v: %v", plan, err)
			}
			target := plan.Targets[0]
			if kind == "historical OCI" && !slices.Equal(target.PrimaryLayers, oci.OCIPrimaryLayers) {
				t.Fatal("missing verified historical layer set")
			}
			before := observation(entry, "passed")
			before.Report.RunnerAsOf = "2025-12-01"
			if entry.Submission.IsOCI() {
				before.ReleaseSHA256 = target.SHA256
			} else {
				before.Report.ArtifactSHA256 = target.SHA256
			}
			reports, err := checkAccepted(t.Context(), entry, nil, []compatibility.Evidence{before}, target, executable, checksum, batchTestRevision, client, inspector.Walk)
			if err != nil {
				t.Fatal(err)
			}
			if len(reports) != 1 || reports[0].Report.Outcome != "unsupported" || reports[0].Release() != target.SHA256 || reports[0].Report.RunnerAsOf != before.Report.RunnerAsOf {
				t.Fatalf("wrong observation: %+v", reports)
			}
			if kind == "historical OCI" {
				legacyReports = reports
			}
			plan, err = PlanCompatibility(t.Context(), index, nil, reports, checksum, batchTestRevision, 1, 0, inspector.PrimaryLayerDigests, io.Discard)
			if err != nil || len(plan.Targets) != 0 {
				t.Fatalf("complete observation queued again: %+v, %v", plan, err)
			}
		})
	}
	legacy := oci
	legacy.OCIPrimaryLayers = nil
	index := Index{Entries: []Entry{legacy, plain}}
	var warnings bytes.Buffer
	unavailable := func(context.Context, string) ([]string, error) {
		return nil, errors.New("offline")
	}
	plan, err := PlanCompatibility(t.Context(), index, nil, legacyReports, checksum, batchTestRevision, 2, 0, unavailable, &warnings)
	if err != nil || len(plan.Targets) != 1 || plan.Targets[0].SHA256 != plain.Submission.Digest() || len(plan.Unavailable) != 1 || plan.Unavailable[0].SHA256 != legacy.Submission.Digest() || !strings.Contains(warnings.String(), "offline") {
		t.Fatalf("old OCI failure blocked independent target: %+v, %q, %v", plan, warnings.String(), err)
	}
	t.Run("rejects wrong digest, binary, URL or release status", func(t *testing.T) {
		target := CompatibilityTarget{Plugin: plain.Name(), Version: plain.Submission.Tag, SHA256: plain.Submission.Digest()}
		wrong := plain
		wrong.URL = "https://example.com/changed"
		for _, tc := range []struct {
			entry          Entry
			pin, errorText string
			statuses       []ReleaseStatus
		}{
			{wrong, checksum, "noncanonical", nil},
			{plain, checksum, "SHA256 mismatch", nil},
			{plain, key("other binary"), "checker executable", nil},
			{plain, checksum, "revoked", []ReleaseStatus{{Status: StatusRevoked, SHA256: target.SHA256}}},
		} {
			replaced := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) { return response(r, "replaced"), nil })}
			reports, err := checkAccepted(t.Context(), tc.entry, tc.statuses, nil, target, executable, tc.pin, batchTestRevision, replaced, nil)
			if err == nil || !strings.Contains(err.Error(), tc.errorText) || reports != nil {
				t.Fatalf("unexpected evidence: %v, %v", reports, err)
			}
		}
	})
}

func TestPlanRejectsUnavailableTargetsOutsideBatchLimit(t *testing.T) {
	target := CompatibilityTarget{Plugin: "github.com/publisher/plugin", Version: "v1", SHA256: key("release")}
	plan := CompatibilityPlan{SchemaVersion: 1, CheckerSHA256: key("checker"), HostRevision: batchTestRevision, Targets: []CompatibilityTarget{}, Unavailable: []CompatibilityTarget{target}}
	if err := plan.Validate(); err != nil {
		t.Fatal(err)
	}
	plan.Targets = []CompatibilityTarget{target}
	if err := plan.Validate(); err == nil {
		t.Fatal("target also marked unavailable")
	}
	plan.Targets = nil
	for i := range MaxCompatibilityTargets {
		plan.Targets = append(plan.Targets, CompatibilityTarget{Plugin: target.Plugin, Version: fmt.Sprintf("v%d", i+2), SHA256: key(fmt.Sprint(i))})
	}
	if err := plan.Validate(); err == nil {
		t.Fatal("unavailable target exceeded total batch size")
	}
}

func TestCompatibilityPlanRequiresAllOCILayersAndSkipsRevokedBytes(t *testing.T) {
	entry := ociCandidate(t)
	layer := entry.OCIPrimaryLayers[0]
	entry.OCIPrimaryLayers = []string{layer, key("additional platform")}
	slices.Sort(entry.OCIPrimaryLayers)
	index := Index{Entries: []Entry{entry}}
	report := layerObservation(entry, layer)
	report.Report.Host = compatibility.Host{Name: "actionlint", Revision: batchTestRevision}
	report.Report.Policy = "actionlint-smoke/1"
	report.Report.SchemaVersion = compatibility.ProtocolVersion
	report.Report.RunnerAsOf = "2026-10-01"
	prior := []compatibility.Evidence{report}
	plan, err := PlanCompatibility(t.Context(), index, nil, prior, report.CheckerSHA256, batchTestRevision, 1, 0, nil, io.Discard)
	if err != nil || len(plan.Targets) != 1 {
		t.Fatalf("partial coverage: %+v, %v", plan, err)
	}
	statuses := []ReleaseStatus{{Status: StatusRevoked, SHA256: layer, Name: "another plugin"}}
	plan, err = PlanCompatibility(t.Context(), index, statuses, prior, report.CheckerSHA256, batchTestRevision, 1, 0, nil, io.Discard)
	if err != nil || len(plan.Targets) != 0 {
		t.Fatalf("scheduled revoked layer: %+v, %v", plan, err)
	}
}

func TestPlanFillsSlotAfterCoveredLegacyOCIAndRotatesWalks(t *testing.T) {
	first := ociCandidate(t)
	layer := first.OCIPrimaryLayers[0]
	first.OCIPrimaryLayers = nil
	first.Submission.Tag = "v1"
	second := first
	second.Submission.Tag = "v2"
	var err error
	second.Submission.Artifact, err = OCIReference("oci://ghcr.io/example/plugin@sha256:" + key("second release"))
	if err != nil {
		t.Fatal(err)
	}
	asset := acceptedFixture(t)
	asset.Submission.Tag = "v3"
	index := Index{Entries: []Entry{second, asset, first}}

	report := layerObservation(first, layer)
	report.Report.Host = compatibility.Host{Name: "actionlint", Revision: batchTestRevision}
	report.Report.Policy = "actionlint-smoke/1"
	report.Report.SchemaVersion = compatibility.ProtocolVersion
	report.Report.RunnerAsOf = "2026-10-01"
	for _, tc := range []struct {
		offset            int
		visited, selected Entry
	}{
		{0, first, asset},
		{1, second, second},
	} {
		t.Run(tc.selected.Submission.Tag, func(t *testing.T) {
			var visits []string
			walk := func(_ context.Context, reference string) ([]string, error) {
				visits = append(visits, reference)
				return []string{layer}, nil
			}
			plan, err := PlanCompatibility(t.Context(), index, nil, []compatibility.Evidence{report}, report.CheckerSHA256, batchTestRevision, 1, tc.offset, walk, io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(visits, []string{tc.visited.Submission.Artifact.Reference()}) {
				t.Fatalf("unexpected inventory walks: %v", visits)
			}
			if len(plan.Targets) != 1 || plan.Targets[0].SHA256 != tc.selected.Submission.Digest() {
				t.Fatalf("planned %v, want %s", plan.Targets, tc.selected.Submission.Tag)
			}
		})
	}
}
