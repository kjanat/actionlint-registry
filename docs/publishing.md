# Check candidates, then publish

Build and package once. Run the candidate check on those bytes in PR CI. The tag
workflow downloads the package and receipt, publishes the same files, and checks
their delivery. Testing a candidate requires no tag, GitHub release, OIDC credential
or registry write access.

## Local candidate check

From a registry checkout with Bun and its Go toolchain installed:

```sh
bun install --frozen-lockfile --filter @kjanat-actionlint/registry-tools
go build -o registry ./cmd/registry
bun scripts/cli.ts check \
  --registry ./registry --actionlint /path/to/actionlint \
  --artifact /path/to/artifacts/plugin.wasm \
  --fixture /path/to/plugin/installation.ts \
  --store registry/plugins --report candidate.json
```

The check uses the registry inspector and catalogue exporter, including existing
plugin/version identity checks. It installs from a temporary local catalogue into
a fresh project and cache. Actionlint creates the configuration and cache
through `plugin install`; the harness does not write installed state itself.

The fixture runs with the installed plugin. The check then removes the temporary
catalogue, repeats the fixture, verifies that the configuration stayed unchanged,
removes the cached artifact and requires a plugin error. For OCI, the artifact
digest identifies the root manifest, rather than the primary Wasm or process
manifest layer. Host processes receive a fresh home and cache and no inherited
credentials. Inspection and installation can acquire public artifacts; fixture
execution uses blocked HTTP proxies. The temporary
directories are removed afterward.

`candidate.json` records the artifact digest and metadata, host binary digest and
version, fixture digest, named behavioral checks, installed version/digest and
offline outcomes. A failed run cannot leave an old success receipt in place.
Publisher authorization still requires OIDC. Store the receipt with the exact
package in your workflow artifacts.

To inspect and export a candidate without running a host:

```sh
./registry candidate --artifact plugin.wasm --store registry/plugins --output trial
```

`trial` must be a new directory. Its catalogue is marked as candidate data and uses
relative paths for local files, or preserves the pinned OCI reference. It cannot
be merged into accepted registration records.
Use the full check above to verify installation and behavior.

### OCI checks before upload

Create a standard ORAS image layout from a packed process manifest, then test the
pinned root without contacting an image registry:

```sh
oras push --oci-layout ./plugin-layout:trial \
  --artifact-type application/vnd.actionlint.plugin.v1+json \
  actionlint-provider.json:application/vnd.actionlint.tool-provider.v1+json
digest="$(oras resolve --oci-layout ./plugin-layout:trial)"
reference="oci://ghcr.io/owner/plugin@${digest}"
bun scripts/cli.ts check \
  --registry ./registry --actionlint ./actionlint \
  --oci "$reference" --oci-layout ./plugin-layout \
  --fixture ./installation.ts --kind manifest --allow-config-processes \
  --report candidate.json
```

The reference names the intended public destination. That image does not need to
exist yet. The registry verifies the local graph with the same admission checks
used for remote sources, including embedded descriptor data. It snapshots only
reachable verified blobs; the harness restores those portable bytes into its
fresh cache, then uses ordinary host installation and behavior checks. Inspection,
installation and fixture execution all run with blocked HTTP proxies.

After a successful check, upload the same layout with ORAS and verify its digest:

```sh
oras cp --from-oci-layout ./plugin-layout:trial ghcr.io/owner/plugin:1.0.0
test "$(oras resolve ghcr.io/owner/plugin:1.0.0)" = "$digest"
```

Pass the same pinned reference and `candidate.json` to the publish action. The
publication tag must match the manifest's version. For Wasm, use `application/wasm`
as the layer media type and omit native-process consent. The shared check action
accepts the same `oci-layout` input; its path is a local build output.

## Behavioral fixture

Provide a TypeScript module exporting functions with these signatures:

```ts
export declare function prepare(context: { directory: string }): Promise<void>;

export declare function verify(context: {
  directory: string;
  run(args: string[], expected?: number): Promise<string>;
  runResult(
    args: string[],
    expected?: number,
  ): Promise<{ stdout: string; stderr: string }>;
}): Promise<{ checks: string[]; probe: string[] }>;
```

`prepare` writes workflow inputs and plugin options before installation. `verify`
asserts diagnostics, locations and relevant behavior, then returns the names of
the checks that passed. For source-following plugins, assert a finding that changes when a sourced
file changes. Checking only that a process exits or returns an array misses that
behavior. The probe must run `check --json`; the harness first requires successful
analysis, then uses the same probe after cache removal.

`run` returns stdout; `runResult` also exposes stderr for assertions about expected failures.
Both check the exit status, defaulting to zero.

Fixtures are trusted publisher code, run in separate child processes. The clean
environment is not an operating-system sandbox. Do not run an untrusted fixture
in a privileged publication job. Guest plugins still run through the host's Wasm
runtime and capability controls.

## GitHub Actions

[`check/action.yml`](../check/action.yml) builds the registry CLI and runs the local
candidate check. Supply `artifact` or `oci`, plus `actionlint` and `fixture`;
`report` defaults to `candidate.json`. Its `sha256` output identifies the tested
release asset bytes or OCI root manifest. On tag refs it checks the candidate against
the accepted records. On other refs it uses an empty store, so dependency updates that
change the package bytes without a version bump still test installation and behavior.

[`publish/action.yml`](../publish/action.yml) accepts:

| Input                    | Purpose                                                                              |
| ------------------------ | ------------------------------------------------------------------------------------ |
| `directory`              | Packaged files, default `artifacts`; every file must appear in `SHA256SUMS`          |
| `asset`                  | Distributed Wasm or process manifest filename                                        |
| `sha256`                 | Exact release asset digest; for Wasm this comes from candidate check                 |
| `oci`                    | Existing OCI reference pinned by `@sha256`; mutually exclusive with `asset`          |
| `candidate-receipt`      | Successful candidate receipt for the exact release asset or OCI root                 |
| `actionlint`, `fixture`  | Host (default: the registry checker's pinned actionlint) and fixture for both checks |
| `allow-config-processes` | Explicit consent for native process fixture checks, default `false`                  |
| `tag`, `repository`      | Existing tag and its public repository, defaulting to the workflow context           |
| `kind`                   | `core`, `component`, or `manifest`, default `component`                              |
| `notes-file`             | UTF-8 release notes; defaults to commit subjects since the previous release          |
| `receipt`                | Publication progress file, default `publication.json`                                |
| `timeout-seconds`        | Publication wait budget, default 1800                                                |

Use the same reviewed registry revision for both actions. A Wasm publishing job
needs `contents: write` and `id-token: write`, and must run on the existing release
tag. Supply the exact host executable and fixture used by the candidate check;
their digests are verified before any remote publication. Enable GitHub immutable
releases before the first publication. The action creates
a draft, uploads missing files, downloads and compares every asset, then makes the
release public and confirms its immutable status. Different bytes under an existing
asset name are an error; reruns never replace assets.

After OIDC submission, the Wasm action waits for `published`, then installs that
exact version from the public catalogue and runs the same fixture and offline
checks. The delivery check uses the actual release tag, including whether it starts
with `v`.
Repository capitalization and optional version prefixes do not change candidate identity.
Upload `publication.json` even when the job fails: it records status and the
validator run. `installation.json` is written after successful delivery verification.

### Process manifests and OCI sources

The local candidate check can exercise process manifest installation and offline
behavior when you provide a fixture and explicitly set
`allow-config-processes: true`. This flag passes `--allow-config-processes` to the
fixture's actionlint checks. Process execution has native host privileges; review
the publisher code and fixture before granting consent. The resulting receipt
records that consent and the checks that passed. It is publisher-run evidence, not
a general compatibility claim; the registry's Wasm compatibility adapter reports
`process/1` as unsupported.

For a process release, run the shared candidate check and publish action on the
same package bytes. The explicit consent applies to both fixture runs:

```yaml
on:
  push:
    tags: ["v*"]
permissions:
  contents: write
  id-token: write
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      # Build actionlint and the manifest package before these steps.
      - uses: kjanat/actionlint-registry/check@<reviewed-commit-sha>
        id: candidate
        with:
          artifact: artifacts/plugin-manifest.json
          kind: manifest
          actionlint: bin/actionlint
          fixture: test/process-fixture.ts
          allow-config-processes: true
          report: candidate.json
      - uses: kjanat/actionlint-registry/publish@<reviewed-commit-sha>
        with:
          directory: artifacts
          asset: plugin-manifest.json
          sha256: ${{ steps.candidate.outputs.sha256 }}
          candidate-receipt: candidate.json
          actionlint: bin/actionlint
          fixture: test/process-fixture.ts
          kind: manifest
          allow-config-processes: true
```

For a release workflow that already uploaded the manifest, the smaller root action
submits it with `contents: read` and `id-token: write`; it does not run a candidate
fixture.

Different plugin IDs can share an OCI repository and authenticated Git tag when
their artifacts have distinct root digests. Each pinned root has its own submission;
admission binds the inspected plugin ID and version to the accepted artifact and
rejects replacement bytes. Identical retries retain their original receipt.

For a public digest-pinned OCI image, use `oci` instead of `artifact` for the
candidate check. Pass that receipt and the same host and fixture to `publish`.
The action does not upload an image or create a release asset. The authenticated
repository, tag and commit still come from the CI OIDC identity; the OCI source
must be publicly retrievable for registry admission. The OCI digest is the
publication's canonical artifact digest, while the source stays recorded as an OCI
reference:

```yaml
on:
  push:
    tags: ["v*"]
permissions:
  contents: read
  id-token: write
jobs:
  register:
    runs-on: ubuntu-latest
    steps:
      - uses: kjanat/actionlint-registry@<reviewed-commit-sha>
        with:
          oci: oci://ghcr.io/owner/plugin@sha256:<64-lowercase-hex-digest>
          kind: component
```

`oci` cannot be combined with `asset` or `sha256`. OCI supports all three execution
kinds when the image contains the corresponding declaration. The publication page
reports OCI references without download links or asset download counts. The root
action above performs submission only. To exercise OCI installation and behavior,
use the same pinned reference in the shared check and publish actions:

```yaml
- uses: kjanat/actionlint-registry/check@<reviewed-commit-sha>
  with:
    oci: ${{ vars.PLUGIN_OCI_REFERENCE }}
    actionlint: bin/actionlint
    fixture: test/installation.ts
- uses: kjanat/actionlint-registry/publish@<reviewed-commit-sha>
  with:
    oci: ${{ vars.PLUGIN_OCI_REFERENCE }}
    candidate-receipt: candidate.json
    actionlint: bin/actionlint
    fixture: test/installation.ts
    kind: component
```

These actions verify the exact root digest, installed package identity and
configuration, offline fixture results and rejection of a missing cached root.
Publication then verifies delivery through the public registry with the same
fixture. For process manifests, supply `kind: manifest` and
`allow-config-processes: true` to both actions. These receipts are publisher-side
evidence for the selected host; registry admission still does not execute plugins
or certify compatibility with other host revisions.

The root [`action.yml`](../action.yml) remains the smaller submission-only entry
point for publishers with an existing release workflow. It returns the submission
ID and current state; `pending` and `validating` require further observation.

## Resume and recovery

Observe a submission without uploading or submitting again:

```sh
bun scripts/cli.ts wait --id SUBMISSION_UUID --sha256 ARTIFACT_SHA256 \
  --receipt publication.json --timeout-seconds 1800
```

The waiter retries network failures, HTTP 408/429 and server errors until its
deadline, respecting `Retry-After`. It prints validator links while work is active.
An exhausted wait fails; it does not report the release as published.

The admission workflow rejects invalid identities or conflicting accepted versions.
Infrastructure failures release the exact claim for retry after 60 seconds, then
120 seconds. After three failed attempts, resubmit identical metadata with fresh
publisher OIDC to start a new attempt sequence. The original submission ID and
accepted bytes stay unchanged. If workflow cleanup cannot run, lease expiry remains
the fallback. See [admission recovery](github-app.md#verify-the-integration).

Run `mise run deploy:worker` from the registry checkout before enabling the workflow's
`consume recover` step; that step calls the Worker's `/v1/claims/:id/retry` endpoint.

Candidate checks test local artifact behavior and installation. GitHub permissions,
immutable-release settings and public catalogue delivery are checked during actual
publication; testing local bytes does not require invoking those remote mutations.
