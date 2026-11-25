package main

import (
	"context"
	"errors"
	"flag"
	"os"

	"registry.actionlint.kjanat.dev/internal/registry"
)

func importCompatibility(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("import-compatibility", flag.ContinueOnError)
	releases := flags.String("store", "registry/plugins", "Accepted releases.")
	statusPath := flags.String("statuses", "registry/status", "Read current withdrawal and revocation records here.")
	evidence := flags.String("compatibility", "registry/compatibility", "Append validated observations to this directory.")
	work := flags.String("plan", "", "Read the plan produced for this checker run.")
	results := flags.String("reports", "", "Read one result file per planned release from this directory.")
	checker := flags.String("checker-sha256", "", "Expected SHA-256 of the pinned checker executable.")
	host := flags.String("host-revision", "", "Expected actionlint revision from the checker build.")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *work == "" || *results == "" || *checker == "" || *host == "" {
		return errors.New("import-compatibility requires --plan, --reports, --checker-sha256 and --host-revision")
	}
	plan, err := registry.ReadCompatibilityPlan(*work)
	if err != nil {
		return err
	}
	index, err := (registry.Store{Directory: *releases}).Load()
	if err != nil {
		return err
	}
	statuses, err := (registry.StatusStore{Directory: *statusPath}).Load(index)
	if err != nil {
		return err
	}
	publication := registry.CompatibilityImport{
		CheckerSHA256: *checker, HostRevision: *host, Statuses: statuses,
		PrimaryLayerDigests: registry.NewOCIInspector().PrimaryLayerDigests, Warnings: os.Stderr,
	}
	return (registry.EvidenceStore{Directory: *evidence}).ImportCompatibility(ctx, index, plan, *results, publication)
}
