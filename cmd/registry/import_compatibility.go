package main

import (
	"errors"
	"flag"

	"registry.actionlint.kjanat.dev/internal/registry"
)

func importCompatibility(args []string) error {
	flags := flag.NewFlagSet("import-compatibility", flag.ContinueOnError)
	releases := flags.String("store", "registry/plugins", "Accepted releases.")
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
	return (registry.EvidenceStore{Directory: *evidence}).ImportCompatibility(index, plan, *results, *checker, *host)
}
