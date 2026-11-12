package validation

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
)

var hostFixtures = map[string]string{
	"core-echo":                       "internal/plugins/execution/module/testdata/engines/echo.wasm",
	"core-missing-export":             "internal/plugins/execution/module/testdata/wat/missing-export.wasm",
	"component-no-sudo":               "internal/plugins/execution/component/testdata/plugins/no-sudo.wasm",
	"component-script":                "internal/plugins/execution/component/testdata/plugins/script-engine.wasm",
	"component-runners":               "internal/plugins/execution/component/testdata/plugins/buildkite-runners.wasm",
	"component-script-0.3.0":          "internal/plugins/execution/component/testdata/plugins/script-engine-0.3.0.wasm",
	"component-template-script-0.3.0": "internal/plugins/execution/component/testdata/plugins/template-script-engine-0.3.0.wasm",
	"component-insecure-download":     "internal/plugins/execution/component/testdata/plugins/insecure-download.wasm",
	"component-wrong-enum":            "internal/plugins/execution/component/testdata/contracts/wrong-enum.wasm",
	"component-wrong-record":          "internal/plugins/execution/component/testdata/contracts/wrong-record.wasm",
	"component-wrong-signature":       "internal/plugins/execution/component/testdata/contracts/wrong-signature.wasm",
}

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
