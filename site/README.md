# Catalogue website

Static Preact pages built from the registry's public JSON export. The site owns
its browser search index, rendering and client behavior.

From the repository root:

```sh
bun install --frozen-lockfile
bun site/cli.ts --input dist --output dist
bun run --cwd site typecheck
bun test --cwd site
bun run --cwd site browser:install
bun run --cwd site test:browser
```

The root Bun workspace owns the shared dependency catalogs and the single lockfile.

Input contains `index.json`, plugin manifests and version records, `statuses.json`,
and optional `downloads.json`. Render a fresh export in place, or pass an empty destination to receive unchanged
copies of public JSON alongside the website. Regenerate the export before
rendering in place again. The builder rejects an existing site so removed
plugins, records and schemas cannot survive a successful rebuild. For the first
build after upgrading, move an existing output made by an older version aside or
choose an empty path. Subsequent exports recognize their own generated files.
For older exports without the file manifest, supply a clean directory containing
only the public registry export.

Every sort has static pages of 20 plugins. Search enhances those pages after its
data loads; sorting and pagination remain usable without JavaScript. URL state
preserves queries, sort and page across sharing and browser history.

HTML dates fall back to UTC. The browser formats dates, times and numeric counts
for its locale and time zone. Sorting always compares UTC instants.

The local browser check uses intercepted static file responses. After deployment,
the Pages workflow requests a missing nested record, checks that Pages serves the
custom 404, and follows its stylesheet and directory links.
`SITE_CHROMIUM` can select an existing Chromium executable for local verification.
