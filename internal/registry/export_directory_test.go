package registry

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestExportRefusesToDeleteUnlistedFiles(t *testing.T) {
	output := filepath.Join(t.TempDir(), "export")
	entry := acceptedFixture(t)
	if err := Export(Index{SchemaVersion: 1, Entries: []Entry{entry}}, output, nil, nil); err != nil {
		t.Fatal(err)
	}
	plugin := filepath.Join(output, "plugins", entry.PluginKey())
	local := filepath.Join(plugin, "notes.txt")
	if err := os.WriteFile(local, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Export(EmptyIndex(), output, nil, nil); err == nil {
		t.Fatal("export deleted a directory containing notes.txt")
	}
	if contents, err := os.ReadFile(local); err != nil || string(contents) != "keep" {
		t.Fatalf("lost local file: %q, %v", contents, err)
	}
	if err := os.Remove(local); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(output, "404.html"), []byte("site"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(filepath.Join(output, siteFiles), []string{"404.html"}); err != nil {
		t.Fatal(err)
	}
	if err := Export(EmptyIndex(), output, nil, nil); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{plugin, filepath.Join(output, "404.html"), filepath.Join(output, siteFiles)} {
		if _, err := os.Stat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("stale output %s: %v", p, err)
		}
	}
}

func TestFailedExportLeavesIndexUnchanged(t *testing.T) {
	output := t.TempDir()
	if err := Export(EmptyIndex(), output, nil, nil); err != nil {
		t.Fatal(err)
	}
	index := filepath.Join(output, "index.json")
	before, err := os.ReadFile(index)
	if err != nil {
		t.Fatal(err)
	}
	want := errors.New("invalid input")
	if err := replaceExport(output, func(staging string) error {
		if err := os.WriteFile(filepath.Join(staging, "index.json"), []byte("partial"), 0o600); err != nil {
			return err
		}
		return want
	}); !errors.Is(err, want) {
		t.Fatal(err)
	}
	after, err := os.ReadFile(index)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("index.json changed after the build failed")
	}
}

func TestExportKeepsDirectoryMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory mode bits are POSIX permissions")
	}
	output := t.TempDir()
	if err := os.Chmod(output, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := Export(EmptyIndex(), output, nil, nil); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(output)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o750 {
		t.Fatalf("export directory permissions changed to %o", mode)
	}
}

func writeGeneration(content string) func(string) error {
	return func(dir string) error {
		return os.WriteFile(filepath.Join(dir, "index.json"), []byte(content), 0o644)
	}
}

func fallbackExchange(string, string) error { return errors.ErrUnsupported }

// This subprocess exits inside the rename operation, without running deferred
// cleanup. The next publisher must recover using only the files on disk.
func TestExportInterruptedPublisher(t *testing.T) {
	phase := os.Getenv("REGISTRY_TEST_INTERRUPT_AFTER")
	if phase == "" {
		return
	}
	dest := os.Getenv("REGISTRY_TEST_DESTINATION")
	rename := func(from, to string) error {
		if phase == "restore" && filepath.Base(from) == "next" {
			return errors.New("installation failed")
		}
		if err := os.Rename(from, to); err != nil {
			return err
		}
		if phase == "backup" && filepath.Base(to) == "previous" ||
			phase == "restore" && filepath.Base(from) == "previous" ||
			(phase == "install" || phase == "first") && filepath.Base(from) == "next" {
			os.Exit(37)
		}
		return nil
	}
	exchange := fallbackExchange
	if phase == "exchange" {
		exchange = func(a, b string) error {
			if err := exchangeExport(a, b); err != nil {
				return err
			}
			os.Exit(37)
			return nil
		}
	}
	t.Fatal(publishExport(dest, func(dir string) error {
		if err := writeGeneration("new")(dir); err != nil {
			return err
		}
		if phase == "build" {
			os.Exit(37)
		}
		return nil
	}, exchange, rename))
}

func TestExportRecoversInterruptedPublication(t *testing.T) {
	for _, phase := range []string{"build", "first", "exchange", "backup", "install", "restore"} {
		t.Run(phase, func(t *testing.T) {
			dir := t.TempDir()
			dest := filepath.Join(dir, "site")
			if phase != "first" {
				if err := replaceExport(dest, writeGeneration("old")); err != nil {
					t.Fatal(err)
				}
			}
			if phase == "exchange" {
				a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
				if err := os.Mkdir(a, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(b, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := exchangeExport(a, b); errors.Is(err, errors.ErrUnsupported) {
					t.Skip("filesystem has no directory exchange")
				} else if err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestExportInterruptedPublisher$")
			cmd.Env = append(os.Environ(), "REGISTRY_TEST_INTERRUPT_AFTER="+phase, "REGISTRY_TEST_DESTINATION="+dest)
			output, err := cmd.CombinedOutput()
			if exit, ok := errors.AsType[*exec.ExitError](err); !ok || exit.ExitCode() != 37 {
				t.Fatalf("publisher did not reach %s: %s (%v)", phase, output, err)
			}
			expected := "old"
			if phase == "exchange" || phase == "install" || phase == "first" {
				expected = "new"
				assertGeneration(t, dest, expected)
			}
			badBuild := errors.New("subsequent build failed")
			if err := replaceExport(dest, func(string) error {
				assertGeneration(t, dest, expected)
				return badBuild
			}); !errors.Is(err, badBuild) {
				t.Fatal(err)
			}
			assertGeneration(t, dest, expected)
			entries, err := os.ReadDir(exportWorkPath(dest))
			if err != nil || len(entries) != 1 || entries[0].Name() != exportLock {
				t.Fatalf("abandoned files after recovery: %v (%v)", entries, err)
			}
		})
	}
}

func assertGeneration(t *testing.T, dir, want string) {
	t.Helper()
	found, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if err != nil || string(found) != want {
		t.Fatalf("index in %s = %q, %v; want %q", dir, found, err, want)
	}
}

func TestExportFallbackRecoversAfterInstallAndRestoreFail(t *testing.T) {
	parent := t.TempDir()
	dest := filepath.Join(parent, "public")
	if err := replaceExport(dest, writeGeneration("old")); err != nil {
		t.Fatal(err)
	}
	installErr, restoreErr := errors.New("install failed"), errors.New("restore failed")
	rename := func(from, to string) error {
		switch filepath.Base(from) {
		case "next":
			return installErr
		case "previous":
			return restoreErr
		default:
			return os.Rename(from, to)
		}
	}
	err := publishExport(dest, writeGeneration("new"), fallbackExchange, rename)
	if !errors.Is(err, installErr) || !errors.Is(err, restoreErr) {
		t.Fatalf("missing publication failures: %v", err)
	}
	work := exportWorkPath(filepath.Join(parent, "public"))
	assertGeneration(t, filepath.Join(work, "previous"), "old")
	assertGeneration(t, filepath.Join(work, "next"), "new")
	if err := publishExport(dest, func(string) error {
		t.Fatal("started build before restoring the backup")
		return nil
	}, fallbackExchange, rename); !errors.Is(err, restoreErr) {
		t.Fatal(err)
	}
	if err := os.Mkdir(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := replaceExport(dest, writeGeneration("third")); err == nil {
		t.Fatal("removed backup after a different writer created the destination")
	}
	assertGeneration(t, filepath.Join(work, "previous"), "old")
	if err := os.Remove(dest); err != nil {
		t.Fatal(err)
	}
	if err := replaceExport(dest, writeGeneration("third")); err != nil {
		t.Fatal(err)
	}
	assertGeneration(t, dest, "third")
}

func TestPublisherRefusesUnownedState(t *testing.T) {
	for _, marker := range []string{"missing", "foreign", "symlink"} {
		t.Run(marker, func(t *testing.T) {
			parent := t.TempDir()
			work := exportWorkPath(filepath.Join(parent, "public"))
			unrelated := filepath.Join(work, "previous")
			if err := os.MkdirAll(unrelated, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := writeGeneration("personal")(unrelated); err != nil {
				t.Fatal(err)
			}
			switch marker {
			case "foreign":
				if err := os.WriteFile(filepath.Join(work, exportLock), []byte("other app"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(filepath.Join(unrelated, "index.json"), filepath.Join(work, exportLock)); err != nil {
					t.Skip(err)
				}
			}
			if err := replaceExport(filepath.Join(parent, "public"), writeGeneration("new")); err == nil {
				t.Fatal("used an unrecognized publication directory")
			}
			assertGeneration(t, unrelated, "personal")
		})
	}
}

func TestConcurrentExportersSerializeBuilds(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "public")
	firstStarted, finishFirst := make(chan struct{}), make(chan struct{})
	firstResult := make(chan error, 1)
	go func() {
		firstResult <- replaceExport(dest, func(dir string) error {
			close(firstStarted)
			<-finishFirst
			return writeGeneration("first")(dir)
		})
	}()
	select {
	case <-firstStarted:
	case err := <-firstResult:
		t.Fatalf("first export did not start: %v", err)
	}
	secondStarted, secondResult := make(chan struct{}), make(chan error, 1)
	go func() {
		secondResult <- replaceExport(dest, func(dir string) error {
			close(secondStarted)
			return writeGeneration("second")(dir)
		})
	}()
	select {
	case <-secondStarted:
		close(finishFirst)
		t.Fatal("concurrent builds used the same staging directory")
	case <-time.After(50 * time.Millisecond):
	}
	close(finishFirst)
	if err := <-firstResult; err != nil {
		t.Fatal(err)
	}
	if err := <-secondResult; err != nil {
		t.Fatal(err)
	}
	assertGeneration(t, dest, "second")
}

func TestPublisherRefusesDestinationSymlinkCreatedDuringBuild(t *testing.T) {
	parent := t.TempDir()
	dest, unrelated := filepath.Join(parent, "public"), t.TempDir()
	if err := replaceExport(dest, func(dir string) error {
		if err := os.Symlink(unrelated, dest); err != nil {
			t.Skip(err)
		}
		return writeGeneration("new")(dir)
	}); err == nil {
		t.Fatal("replaced a symlink")
	}
	if target, err := os.Readlink(dest); err != nil || target != unrelated {
		t.Fatalf("changed symlink: %s, %v", target, err)
	}
}

func TestExchangeKeepsPublicDirectoryVisible(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "public")
	if err := replaceExport(dest, writeGeneration("initial")); err != nil {
		t.Fatal(err)
	}
	probe := filepath.Join(dir, "probe")
	if err := os.Mkdir(probe, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := exchangeExport(dest, probe); errors.Is(err, errors.ErrUnsupported) {
		t.Skip("filesystem has no directory exchange")
	} else if err != nil {
		t.Fatal(err)
	}
	if err := exchangeExport(probe, dest); err != nil {
		t.Fatal(err)
	}

	started, stop := make(chan struct{}), make(chan struct{})
	reader := make(chan error, 1)
	go func() {
		close(started)
		for {
			if _, err := os.Stat(dest); err != nil {
				reader <- err
				return
			}
			select {
			case <-stop:
				reader <- nil
				return
			default:
			}
		}
	}()
	<-started
	defer func() {
		close(stop)
		if err := <-reader; err != nil {
			t.Error(err)
		}
	}()
	for range 25 {
		if err := replaceExport(dest, writeGeneration("updated")); err != nil {
			t.Fatal(err)
		}
	}
}

func TestExportWorkDoesNotRestrictPublicParentPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory mode bits are POSIX permissions")
	}
	dir := t.TempDir()
	control := filepath.Join(dir, "control")
	if err := os.Mkdir(control, 0o755); err != nil {
		t.Fatal(err)
	}
	want, err := os.Stat(control)
	if err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(dir, "www")
	if err := replaceExport(filepath.Join(parent, "public"), writeGeneration("new")); err != nil {
		t.Fatal(err)
	}
	got, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	if got.Mode().Perm() != want.Mode().Perm() {
		t.Fatalf("new public parent mode = %o, want %o", got.Mode().Perm(), want.Mode().Perm())
	}
}

func TestExportWorkIsPrivateToTheDestination(t *testing.T) {
	parent := t.TempDir()
	for _, base := range []string{"foo", "bar"} {
		dest := filepath.Join(parent, base)
		if err := replaceExport(dest, writeGeneration(base)); err != nil {
			t.Fatal(err)
		}
		if filepath.Dir(exportWorkPath(dest)) != parent {
			t.Fatal("unrelated exports share a private parent")
		}
	}
	// Both basenames fit, but only the composed spelling fits with the suffix.
	composed := strings.Repeat("é", 80)
	decomposed := strings.Repeat("e\u0301", 80)
	if filepath.Dir(exportWorkPath(filepath.Join(parent, composed))) != filepath.Dir(exportWorkPath(filepath.Join(parent, decomposed))) {
		t.Fatal("canonically equivalent basenames chose different work directories")
	}
	long := strings.Repeat("x", 252)
	a, b := filepath.Join(parent, long), filepath.Join(parent, strings.ToUpper(long))
	if filepath.Dir(exportWorkPath(a)) != filepath.Dir(exportWorkPath(b)) || exportWorkPath(a) == exportWorkPath(b) {
		t.Fatal("long names must share a folded parent but use their native basename for the lock")
	}
	if runtime.GOOS != "windows" {
		// Filesystems with a smaller component limit cannot create this destination either.
		if err := os.Mkdir(a, 0o755); err != nil {
			t.Skip(err)
		}
		if err := replaceExport(a, writeGeneration("long")); err != nil {
			t.Fatal(err)
		}
		assertGeneration(t, a, "long")
	}
}
