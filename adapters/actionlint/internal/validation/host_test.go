package validation

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"actionlint.kjanat.dev/v2/internal/model/lifecycle"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
)

var hostFixtures = map[string]string{
	"core-echo":                       "internal/plugins/pluginexecution/module/testdata/engines/echo.wasm",
	"core-missing-export":             "internal/plugins/pluginexecution/module/testdata/wat/missing-export.wasm",
	"component-no-sudo":               "internal/plugins/pluginexecution/component/testdata/plugins/no-sudo.wasm",
	"component-managed-no-sudo":       "internal/plugins/pluginexecution/component/testdata/plugins/managed-no-sudo.wasm",
	"component-script":                "internal/plugins/pluginexecution/component/testdata/plugins/script-engine.wasm",
	"component-runners":               "internal/plugins/pluginexecution/component/testdata/plugins/buildkite-runners.wasm",
	"component-runners-0.3.0":         "internal/plugins/pluginexecution/component/testdata/plugins/runner-support-0.3.0.wasm",
	"component-script-0.3.0":          "internal/plugins/pluginexecution/component/testdata/plugins/script-engine-0.3.0.wasm",
	"component-template-script-0.3.0": "internal/plugins/pluginexecution/component/testdata/plugins/template-script-engine-0.3.0.wasm",
	"component-insecure-download":     "internal/plugins/pluginexecution/component/testdata/plugins/insecure-download.wasm",
	"component-wrong-enum":            "internal/plugins/pluginexecution/component/testdata/contracts/wrong-enum.wasm",
	"component-wrong-record":          "internal/plugins/pluginexecution/component/testdata/contracts/wrong-record.wasm",
	"component-wrong-signature":       "internal/plugins/pluginexecution/component/testdata/contracts/wrong-signature.wasm",
}

var testAsOf = lifecycle.DateOf(time.Date(2026, time.December, 8, 0, 0, 0, 0, time.UTC))

var hostDirectory = sync.OnceValues(func() (string, error) {
	output, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", hostModule).Output()
	return strings.TrimSpace(string(output)), err
})

func hostFixture(t *testing.T, name string) string {
	t.Helper()
	relative, ok := hostFixtures[name]
	if !ok {
		t.Fatalf("unknown host fixture %q", name)
	}
	directory, err := hostDirectory()
	if err != nil || directory == "" {
		t.Fatalf("locate %s: %v", hostModule, err)
	}
	return filepath.Join(directory, filepath.FromSlash(relative))
}

func TestHostCommitMatchesModuleRequirement(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	file, err := modfile.ParseLax("go.mod", data, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, requirement := range file.Require {
		if requirement.Mod.Path != hostModule {
			continue
		}
		revision, err := module.PseudoVersionRev(requirement.Mod.Version)
		if err != nil {
			t.Fatal(err)
		}
		if HostCommit != revision {
			t.Fatalf("HostCommit %q, go.mod requires %s", HostCommit, requirement.Mod.Version)
		}
		return
	}
	t.Fatalf("go.mod does not require %s", hostModule)
}
