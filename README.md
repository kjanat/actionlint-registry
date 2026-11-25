# actionlint plugin registry

[Browse the catalogue](https://plugins.actionlint.kjanat.dev/) to find plugins for
[actionlint](https://github.com/kjanat/actionlint). Each plugin page lists its
releases and the command to install a specific version.

## Install a plugin

From your project directory, install Ruff and run actionlint.

```sh
actionlint plugin install ruff
actionlint check
```

Commit the updated actionlint configuration. It pins the plugin version.
Run `actionlint plugin sync` after cloning the project or in CI.

## Publishing

Publish a release asset or OCI image. The registry verifies the publisher and
artifact digest before listing the release. See the [metadata requirements](docs/metadata.md)
and the publishing instructions for [GitHub Actions](docs/publishing.md#github-actions)
or [GitLab CI](docs/publishing.md#gitlabcom).

[Registry JSON index](https://plugins.actionlint.kjanat.dev/index.json) ·
[Plugin settings schemas](https://plugins.actionlint.kjanat.dev/schemas/plugin-config.schema.json) ·
[Contributing](CONTRIBUTING.md)
