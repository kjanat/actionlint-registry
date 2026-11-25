#!/usr/bin/env bash
set -euo pipefail

# Use the same actionlint and real example provider as the registry's pinned host.
tombi=${1:-$(command -v tombi)}
yaml_lint="$PWD/node_modules/.bin/yaml-schema-lint"
project=$(mktemp -d)
trap 'rm -rf "$project"' EXIT
go -C adapters/actionlint build -o "$project/actionlint" actionlint.kjanat.dev/v2/cmd/actionlint
host=$(go -C adapters/actionlint list -m -f '{{.Dir}}' actionlint.kjanat.dev/v2)
cd "$project"
git init --quiet
mkdir .github

write_configs() {
  cat >.github/actionlint.toml <<EOF
#:schema ./actionlint.local.schema.json
plugins = []
[tools.psscriptanalyzer.config]
Severity = ["$1"]
EOF
  cat >.github/actionlint.yaml <<EOF
# yaml-language-server: \$schema=./actionlint.local.schema.json
plugins: []
tools:
  psscriptanalyzer:
    config:
      Severity: [$1]
EOF
}

write_configs Warning
./actionlint config schema --plugin "$host/plugins/examples/psscriptanalyzer/provider.json" >.github/actionlint.local.schema.json
"$tombi" lint --offline --error-on-warnings .github/actionlint.toml
"$yaml_lint" --no-schema-store .github/actionlint.yaml

write_configs InvalidSeverity
if "$tombi" lint --offline --error-on-warnings --diagnostics-format=json --diagnostics-file=toml-errors.json .github/actionlint.toml; then
  echo "Tombi accepted an invalid plugin severity" >&2
  exit 1
fi
jq -e 'any(.[]; .code == "jsonschema/enum" and (.message | contains("Warning")))' toml-errors.json

if "$yaml_lint" --no-schema-store --format json --output-file yaml-errors.json .github/actionlint.yaml; then
  echo "YAML language service accepted an invalid plugin severity" >&2
  exit 1
fi
jq -e 'any(.[].diagnostics[]; .message | contains("Warning"))' yaml-errors.json
