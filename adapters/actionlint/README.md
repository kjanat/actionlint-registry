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
report to stdout. It implements report protocol 3: `--protocol` prints `3`, and the
report's `runner_as_of` is the runner assessment date. The date is
the current UTC date unless `--runner-as-of YYYY-MM-DD` sets it; the registry
always sets it. For a component, the report's `imports` and `exports` are the
lists the host's `component.ReadInterfaces` reads from the bytes, whatever the
outcome. Run the checker through the registry's `check` command to verify
the accepted artifact's checksum, isolate inherited credentials, and store the
report.
The process boundary does not provide an operating-system sandbox.

The checker uses the actionlint v2 revision required in `go.mod` and reports it
from the build. Its tests load runtime fixtures from that host module.
It supports core ABI 1. Components pass the host's own admission decision,
`component.Admit`, so the checker accepts the components that host revision
loads, with the roles that decision returns. The metadata `interface` must name one
of the component's exports. A component whose declared interface is missing from
its exports, or one the host rejects, returns `failed`. A declared interface the
host does not load, or an import the host does not provide, returns `unsupported`.
The host validates exported component types. A WIT source checksum also covers
documentation comments, so a different checksum alone does not reject an analyzer.
Each admitted role runs its own checks. Analyzers check a sample workflow twice
and an empty workflow. Script engines validate default options and repeated
diagnostic calls. Runner providers resolve a workflow's runner selector with
missing evidence for each declared target, through the host's runner resolution;
vendor-specific snapshot behavior belongs in the publisher's candidate fixtures.
Reference resolvers resolve a full commit ID twice against an in-memory repository.
The embedded `descriptor` must match the runtime descriptor of the role that
`interface` names. Admission and the shared candidate check reject `failed`.
