# Runtime fixtures

The component fixtures and `core-missing-export.wasm` match the files in
[actionlint at 99a250b29aaadfdb2d95a0c6ab954d3f9f11bdc8](https://github.com/kjanat/actionlint/tree/99a250b29aaadfdb2d95a0c6ab954d3f9f11bdc8).
`core-echo.wasm` comes from [actionlint at abe9f897d9d8d019c572142626b8f055352f2ac7](https://github.com/kjanat/actionlint/tree/abe9f897d9d8d019c572142626b8f055352f2ac7).
They are licensed under the MIT license. `ACTIONLINT-LICENSE` contains the upstream copyright notice.

| Local file                       | Upstream path                                                                  |
| -------------------------------- | ------------------------------------------------------------------------------ |
| `core-echo.wasm`                 | `internal/plugins/core/testdata/engines/echo.wasm`                             |
| `core-missing-export.wasm`       | `internal/plugins/execution/module/testdata/wat/missing-export.wasm`           |
| `component-no-sudo.wasm`         | `internal/plugins/execution/component/testdata/plugins/no-sudo.wasm`           |
| `component-script.wasm`          | `internal/plugins/execution/component/testdata/plugins/script-engine.wasm`     |
| `component-runners.wasm`         | `internal/plugins/execution/component/testdata/plugins/buildkite-runners.wasm` |
| `component-wrong-enum.wasm`      | `internal/plugins/execution/component/testdata/contracts/wrong-enum.wasm`      |
| `component-wrong-record.wasm`    | `internal/plugins/execution/component/testdata/contracts/wrong-record.wasm`    |
| `component-wrong-signature.wasm` | `internal/plugins/execution/component/testdata/contracts/wrong-signature.wasm` |

The incompatible components export the expected interface name, but their exported
types do not match the contract. The tests must reject them before invoking them.

The host can load `core-echo.wasm`, but this checker rejects it because it omits
rule descriptors. The tests in `core_fixture_test.go` generate core fixtures that
can pass validation. One uses Ruff's registration format to test the bundled
backend without generic shell selectors.

The `component-script-0.3.0.wasm` and `component-template-script-0.3.0.wasm`
fixtures come from the corresponding files in `internal/plugins/execution/component/testdata/plugins`
at [actionlint afaa8f8a5c537d0e718d6a9045c7b81c45811c61](https://github.com/kjanat/actionlint/tree/afaa8f8a5c537d0e718d6a9045c7b81c45811c61).
