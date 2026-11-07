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
report to stdout. Run it through the registry's `check` command to verify the
accepted artifact's checksum, isolate inherited credentials, and store the report.
The process boundary does not provide an operating-system sandbox.

The checker uses actionlint v2 at `afaa8f8a5c537d0e718d6a9045c7b81c45811c61`.
It supports core ABI 1, analyzer and runner-provider WIT roles at 0.2.0, and
script-engine at 0.2.0 and 0.3.0. A template-effects extension must match its
script-engine version.
The host validates exported component types. A WIT source checksum also covers
documentation comments, so a different checksum alone does not reject an analyzer.
Script engines validate default options and repeated diagnostic calls. Runner
providers resolve a selector with missing evidence for each declared target;
vendor-specific snapshot behavior belongs in the publisher's candidate fixtures.
Unknown contracts return `unsupported`; understood contracts that fail validation
return `failed`. Neither result rejects a release from the registry.

When updating the host dependency, update `HostCommit`, contract constants, and
fixtures together. Run the module's tests and linter before using the new checker.
