package main

import (
	"context"
	"errors"
	"flag"
	"os"

	"registry.actionlint.kjanat.dev/internal/registry"
)

func runAcceptedCompatibility(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	plugins := flags.String("store", "registry/plugins", "Read accepted plugin releases here.")
	statusPath := flags.String("statuses", "registry/status", "Read withdrawal and revocation records here.")
	history := flags.String("compatibility", "registry/compatibility", "Read prior checker observations here.")
	checksum := flags.String("checker-sha256", "", "Expected SHA-256 of the checker executable.")
	host := flags.String("host-revision", "", "Expected actionlint host revision reported by the checker.")
	output := flags.String("report", "", "Write the plan or completed reports to this JSON file.")
	var target registry.CompatibilityTarget
	var checker string
	var limit, offset int
	if args[0] == "plan-compatibility" {
		flags.IntVar(&limit, "limit", registry.MaxCompatibilityTargets, "Maximum number of releases to plan.")
		flags.IntVar(&offset, "offset", 0, "Start at this index in the list of releases missing reports, wrapping at the end.")
	} else {
		flags.StringVar(&target.Plugin, "plugin", "", "Canonical plugin selector.")
		flags.StringVar(&target.Version, "version", "", "Exact accepted release tag.")
		flags.StringVar(&target.SHA256, "sha256", "", "SHA-256 of the accepted release.")
		flags.StringVar(&checker, "checker", "", "Path to the pinned actionlint checker.")
	}
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || *output == "" {
		return errors.New("a --report output path is required; positional arguments are not accepted")
	}
	index, err := (registry.Store{Directory: *plugins}).Load()
	if err != nil {
		return err
	}
	prior, err := (registry.EvidenceStore{Directory: *history}).Load(index)
	if err != nil {
		return err
	}
	statuses, err := (registry.StatusStore{Directory: *statusPath}).Load(index)
	if err != nil {
		return err
	}
	if args[0] == "plan-compatibility" {
		plan, err := registry.PlanCompatibility(ctx, index, statuses, prior, *checksum, *host, limit, offset, registry.NewOCIInspector().Walk, os.Stderr)
		if err != nil {
			return err
		}
		return registry.WriteJSON(*output, plan)
	}
	reports, err := registry.CheckAccepted(ctx, index, statuses, prior, target, checker, *checksum, *host)
	if err != nil {
		return err
	}
	return registry.WriteJSON(*output, reports)
}
