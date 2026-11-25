# Embedded plugin metadata

WASM admission requires exactly one **top-level** `actionlint.plugin` custom section
containing a JSON object of at most 1 MiB. Process packages instead use a JSON
manifest with inline metadata. Duplicate sections or JSON members, malformed
section lengths, invalid UTF-8, and missing metadata are rejected. Metadata inside
a component's nested core module does not describe the component. The registry
never changes a publisher's artifact.

Both formats require `metadata_version: 1`, `id`, `name`, `description`, `license`,
`repository`, and `plugin_version`. The repository must be the canonical HTTPS URL
of the authenticated release repository. The version must match the release tag
after removing at most one leading lowercase `v` from each. License information is
a publisher declaration, not an independent license audit.

The registry retains the entire metadata object, including unknown fields and
exact JSON numbers. Admission compiles each declared `config_schema`,
`rules[].options_schema`, and `descriptor.options_schema` as JSON Schema Draft
2020-12. A declaration is an object or boolean. A rule with an options schema
must have a non-empty category and name, unique together within the release.

Each settings declaration is self-contained. A reference must resolve to a
schema in that same declaration, including an embedded resource under `$defs`.
Admission checks unused definitions as well as the root and rejects unsupported
dialects, duplicate resource identifiers, and unresolved references. It never
fetches a publisher URL. Export assigns each resource a version-specific
identifier and updates its `$ref` and `$dynamicRef` targets, preserving
anchors, exact numbers, and literal values in annotations.

The actionlint host determines where settings apply in a project configuration
and which providers accept a settings file. Other rule metadata, capabilities,
and facts remain publisher declarations.

## Multiple plugins in one repository

Use a repository-qualified `id`, such as `github.com/owner/repo/trailing-space`,
for each package. Keep `repository` set to `https://github.com/owner/repo`: that
field identifies the authenticated publisher, while the ID distinguishes its
packages. New qualified packages use the full lowercase ID as their install
selector and retain separate version and digest records. Existing registrations
keep their original selectors.

For example, `actionlint plugin install github.com/owner/repo/trailing-space@v1.0.0`
selects that package. The candidate exporter uses the same selector, so the shared
check verifies the package identity before publication.

## Core modules

Set `transport` to `"wasm-core-json"` and `abi_version` to a positive unsigned
32-bit integer. The registry records `wasm-core-json/<abi_version>` as the declared
contract. Admission does not require the registry's checker to support that ABI.

## Components

Set `transport` to `"wasm-component"`, `interface` to the identity of one of the
component's top-level instance exports, and `wit_sha256` to the lowercase SHA-256
checksum of the canonical WIT.
Admission rejects `contract_sha256`.
These are declarations. A compatible host's checker verifies the exported types;
admission reads the declaration without instantiating the component.

For example, a component can declare:

```json
{
  "metadata_version": 1,
  "id": "example-check",
  "name": "Example check",
  "description": "Checks an example workflow property",
  "license": "MIT",
  "repository": "https://github.com/owner/example-plugin",
  "plugin_version": "1.0.0",
  "transport": "wasm-component",
  "interface": "example:checks/analyzer@2.0.0",
  "wit_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "descriptor": {
    "name": "example-check",
    "future_fact": "workflow-declarations"
  }
}
```

The checksum above is illustrative. Unknown contracts are catalogued without a
compatibility claim.

For `kjanat:actionlint/runner-provider@0.2.0` and `@0.3.0`, `descriptor` contains
the provider's `name`, `version` and `targets` from its runtime `describe()`
result. The Wasm compatibility adapter compares all three fields and exercises
the provider with a missing snapshot through actionlint's own runner resolution,
which rejects invalid answers and support catalogues. Targets describe supported
platforms, so their order does not affect the comparison. The package `id`,
display `name` and `plugin_version` identify the distributed release and may
differ from the provider descriptor. The adapter rejects a provider that takes the
name of an actionlint built-in provider for one of that built-in's targets, such
as `github` or `snapshot` for the `github` target; actionlint never selects it there.

## Process manifests

A process package is a single UTF-8 JSON file named `.json` or `.json.gz`. Its
uncompressed document has `schema_version: 1`, root `transport: "process"`, and a
`metadata` object. Metadata uses `metadata_version: 1`, the same discovery fields
above, and `transport: "process"`:

```json
{
  "schema_version": 1,
  "id": "example-process",
  "version": "1.0.0",
  "transport": "process",
  "process": { "entry": "example-process" },
  "metadata": {
    "metadata_version": 1,
    "id": "example-process",
    "name": "Example process plugin",
    "description": "Runs a publisher-hosted process",
    "license": "MIT",
    "repository": "https://github.com/owner/example-plugin",
    "plugin_version": "1.0.0",
    "transport": "process"
  }
}
```

The checksum covers the exact distributed manifest bytes (compressed bytes for
`.json.gz`). Manifest admission validates and records this declaration; it does
not run the declared process, inspect companion files, or establish process
compatibility. Publish companions as separate digest-pinned OCI artifacts when
needed. Process plugins execute with native host privileges. Only install one
after explicit review and consent; the Wasm guest capability controls do not
apply. The shared candidate fixture route requires the explicit
`--allow-config-processes` flag before its fixture may run a process plugin. The
registry's separate Wasm compatibility adapter reports `process/1` as unsupported;
a successful publisher fixture is not a general compatibility claim. At runtime,
configuration-selected native processes also require that opt-in; an explicit
`actionlint check --plugin PATH` or `--plugin oci://...@sha256:...` invocation
selects that source directly.

## Admission limits

The distributed file may be at most 64 MiB. Gzip expansion is limited to 128 MiB.
Checksums always cover the distributed bytes, including compression. The inspector
validates container framing and discovery metadata. It does not validate WASM
instructions, verify WIT semantics, or execute guest code.

`go run registry.actionlint.kjanat.dev/cmd/registry@master inspect --artifact plugin.wasm` inspects declarations locally.
It does not authorize or publish a release.

## Compatibility checks

The [actionlint adapter](../adapters/actionlint/) checks the contract understood by
its own host dependency. Its checks cover ABI or WIT compatibility, embedded/runtime
metadata agreement, application registration, default configuration, repeated sample
analysis, diagnostic positions, and fixes. Its Ruff sample requires F821, and its
ShellCheck sample requires SC2086. These samples do not prove correctness for every input.

The registry's `check` command snapshots the artifact before starting an explicitly
selected checker. With `--plugin` and `--version`, it also checks the accepted
version's digest and saves the report beside that version. Without those flags it
checks an unpublished candidate and prints its report without requiring a release.
The checker has a 45-second process
deadline and bounded stdout/stderr. The bundled adapter gives guest calls a
10-second deadline and limits guest linear memory. `GOMEMLIMIT` guides garbage
collection; it does not impose an operating-system memory limit. The checker
process has no inherited registry credentials, but it is not an OS sandbox.

The versioned [JSON report protocol](../schemas/compatibility.schema.json) records
`passed`, `failed`, or `unsupported` for a particular artifact, host revision, and
policy. A checker crash produces no compatibility evidence. Missing evidence means
untested. Admission, the shared candidate check, and publication of new versions
reject `failed` reports. A checker may report `unsupported` for an accepted release.
No outcome changes an existing release record. Admission stores its
report under `registry/compatibility` together with the accepted record. With
`--candidate`, `admit` writes the report to the candidate's sibling
`compatibility` directory unless `--compatibility` names another. `merge` rejects
a new version that has no report in `--candidate-compatibility`. An OCI
candidate must include a report for each distinct verified primary layer.

For an OCI release or candidate, admission, `check` and the shared candidate check
run the checker on the primary layer of each platform. Each report names the layer
it hashed in `artifact_sha256`, and its record names the root manifest digest in
`release_sha256`. The accepted version records the verified primary layer
digests in `oci_primary_layers`. Pass the pinned `oci://` reference as
`check --artifact`, and add `--oci-layout` to read the graph from a local image
layout. With `--plugin` and
`--version`, the reference must equal the accepted release's reference, and the
registry stores and links the records under its root digest. Without them, `check`
prints one record per line, and `--report` writes the records as a JSON array.
Inspection rejects an OCI release whose platform layers carry different embedded
metadata, compared as canonical JSON. actionlint installs a platform only when its
metadata equals the release's.

Before each check the registry runs the checker with `--protocol`, with a
5-second limit. A protocol 2 or 3 checker prints its version; a protocol 1
checker treats the argument as a missing artifact, exits with status 1 and prints
nothing. A probe that times out, ends by a signal or exits with any other status,
such as a Go panic's 2, fails the check. Protocol 2 and 3 reports carry a
required `runner_as_of`, the runner assessment date the checker used. The
registry passes every protocol 2 and 3 checker `--runner-as-of`.
`check --plugin --version` passes the date of the version's earliest dated
record. Admission, unpublished checks and versions without a dated record pass
the current UTC date, taken before the checker starts. The registry rejects a
report whose date differs from the date it passed. A protocol 1 checker receives
no date and its records stay undated.

A protocol 3 report on a component can list the component's `imports` and
`exports`. `imports` holds every top-level import name, spelled exactly as in the
binary. `exports` holds the top-level exports whose kind is an instance. A report
carries both lists or neither. Export copies both lists into the component's
version entry in its plugin `index.json`:

```json
{
  "version": "v1.2.0",
  "record": "versions/<sha256(tag)>.json",
  "compatibility": [],
  "imports": ["kjanat:actionlint/invocation-context@0.2.0"],
  "exports": ["kjanat:actionlint/analyzer@0.2.0"]
}
```

Export includes both lists when the reports agree and every expected artifact
has a report that lists them. OCI versions accepted before the registry recorded
layer digests omit the lists. actionlint checks the downloaded bytes in either case.
Running `check --plugin --version` with a protocol 3 checker can supply missing
lists for a version with known coverage.

For release preparation, the [shared candidate check](publishing.md) also installs
the exact local bytes through actionlint and executes a publisher-supplied fixture.
Its receipt identifies the tested host binary, fixture and checks. A fixture is
trusted publisher code and should assert the behavior changed by the release.
The shared publish action requires this successful receipt before uploading assets.
