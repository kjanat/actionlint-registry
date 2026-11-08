# Publication inbox

The Worker `actionlint-plugin-registry` serves `registry.actionlint.kjanat.dev`.
Plugin release workflows submit releases to it with an OIDC token. The Worker
queues each submission in a SQLite Durable Object and starts the admission
workflow through the registry's [GitHub App](../docs/github-app.md). The admission
workflow claims the submission, validates the release and reports the result. The
Worker never downloads or runs plugins.

Do not commit publisher tokens, GitHub App keys or Cloudflare credentials.

## Authentication

- Publisher tokens use the audience `https://registry.actionlint.kjanat.dev`.
  Validator tokens use `https://registry.actionlint.kjanat.dev/validator`.
- The Worker accepts GitHub Actions and GitLab.com tokens up to ten minutes old.
- GitHub publishers run from a tag in their own public repository, on a `push`,
  `release` or `workflow_dispatch` event. The Worker rejects pull request tokens.
- GitLab publishers run a tag pipeline in a public project, triggered by `push` or
  `web`, with CI configuration from the same tag.
- Validator tokens must come from `.github/workflows/admission.yml` on `master` of
  this repository, on a `schedule` or `workflow_dispatch` event.

## HTTP API

| Request                         | Token     | Purpose                          |
| ------------------------------- | --------- | -------------------------------- |
| `POST /v1/submissions`          | publisher | Queue a release                  |
| `GET /v1/submissions/<id>`      | none      | Read the status                  |
| `POST /v1/claims`               | validator | Claim the next submission        |
| `POST /v1/claims/<id>/complete` | validator | Report `published` or `rejected` |
| `GET /health`                   | none      | Returns `{"status":"ok"}`        |

A submission looks like this:

```json
{
  "schema_version": 1,
  "provider": "github",
  "repository": "owner/plugin",
  "tag": "v1.0.0",
  "asset": "plugin.wasm",
  "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "kind": "core"
}
```

`provider` is `github` or `gitlab`. `kind` is `core` or `component`. The asset ends
in `.wasm` or `.wasm.gz`. A status is `pending`, `validating`, `published`,
`rejected` or `failed`. Repeating a submission returns the existing one. A tag's
asset bytes can never change. New bytes need a new tag.

## Limits and retries

- A publisher can have ten open submissions and make thirty submissions per hour.
  The registry holds at most 1,000 open submissions.
- A claim holds a sixty-minute lease. After three expired leases the submission
  becomes `failed`. The publisher can retry it with identical metadata and a fresh
  token.
- If the GitHub App dispatch fails, the next scheduled admission run picks up the
  submission. Workers Logs records `registry-dispatch-succeeded` and
  `registry-dispatch-failed` events with the submission ID.

## Checks

```sh
bun install --frozen-lockfile
bun run --cwd worker typecheck
bun test --cwd worker
bun run --cwd worker check:bundle
```

## Deployment

Run `bunx wrangler deploy` in this directory. A deploy applies the observability
settings in `wrangler.jsonc` over the dashboard's settings.

Renaming this repository requires a matching change to the GitHub App dispatcher,
the validator workflow identity, the Go vanity metadata and `REGISTRY_WORKFLOW_REF`.
