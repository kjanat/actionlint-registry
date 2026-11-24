# actionlint compatibility checker

This unpublished Go module validates plugins with actionlint's private host
implementation. Its module path, `actionlint.kjanat.dev/v2/registry/validation`,
allows it to import the host's `internal` packages under Go's import rules.
The registry invokes the checker as a separate process rather than importing
the host implementation into its admission service.

Build it from the repository root with:

```sh
go -C adapters/actionlint build -o ../../actionlint-checker .
```

The executable accepts one local artifact path and writes one JSON compatibility
report to stdout. It implements report protocol 2: `--protocol` prints `2`, and the
report's `runner_as_of` is the runner assessment date. The date is
the current UTC date unless `--runner-as-of YYYY-MM-DD` sets it; the registry
always sets it. Run the checker through the registry's `check` command to verify
the accepted artifact's checksum, isolate inherited credentials, and store the
report.
The process boundary does not provide an operating-system sandbox.

The checker uses the actionlint v2 revision required in `go.mod` and reports it
from the build. Its tests load runtime fixtures from that host module.
It supports core ABI 1, the analyzer WIT role at 0.2.0, and runner-provider and
script-engine at 0.2.0 and 0.3.0. The host module supplies these interface names.
A template-effects extension must match its script-engine version.
The host validates exported component types. A WIT source checksum also covers
documentation comments, so a different checksum alone does not reject an analyzer.
Script engines validate default options and repeated diagnostic calls. Runner
providers resolve a workflow's runner selector with missing evidence for each
declared target, through the host's runner resolution;
vendor-specific snapshot behavior belongs in the publisher's candidate fixtures.
Unknown contracts return `unsupported`; understood contracts that fail validation
return `failed`. Admission and the shared candidate check reject `failed`.

A host update that changes a WIT contract needs matching contract constants. The
module's tests and linter fail until they match.
