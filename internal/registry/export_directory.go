package registry

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/rogpeppe/go-internal/lockedfile"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

const exportFiles = ".registry-export-files.json"
const siteFiles = ".registry-site-files.json"

const exportWorkSuffix = ".registry-export"
const longExportWorkPrefix = ".registry-export-long-"
const exportLock = "publish.lock"
const lockContents = "actionlint-registry export v1\n"

func replaceExport(directory string, build func(string) error) error {
	return publishExport(directory, build, exchangeExport, os.Rename)
}

type renameDirectory func(string, string) error

func exportWorkPath(dest string) string {
	parent, base := filepath.Split(dest)
	folded := norm.NFD.String(cases.Fold().String(norm.NFD.String(base)))
	// Pick the same layout across spelling aliases, allowing four UTF-8 bytes per rune.
	if 1+utf8.UTFMax*utf8.RuneCountInString(folded)+len(exportWorkSuffix) <= 255 {
		return filepath.Join(parent, "."+base+exportWorkSuffix)
	}
	// The basename still distinguishes spellings on case-sensitive filesystems.
	return filepath.Join(parent, longExportWorkPrefix+key(folded), base)
}

func publishExport(directory string, build func(string) error, exchange, rename renameDirectory) (err error) {
	dest, err := filepath.Abs(directory)
	if err != nil {
		return err
	}
	if err := safePath(dest); err != nil {
		return err
	}
	for p := dest; filepath.Dir(p) != p; p = filepath.Dir(p) {
		name := strings.ToLower(filepath.Base(p))
		if strings.HasPrefix(name, ".") && strings.HasSuffix(name, exportWorkSuffix) || strings.HasPrefix(name, longExportWorkPrefix) {
			return fmt.Errorf("export destination uses reserved directory %s", p)
		}
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	if rel, err := filepath.Rel(dest, cwd); err == nil && filepath.IsLocal(rel) {
		return fmt.Errorf("export destination contains the working directory: %s", dest)
	}
	parent := filepath.Dir(dest)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	work := exportWorkPath(dest)
	lock, err := lockExportWork(work)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, lock.Close()) }()
	next := filepath.Join(work, "next")
	previous := filepath.Join(work, "previous")
	if err := recoverExport(dest, next, previous, rename); err != nil {
		return err
	}
	if err := os.Mkdir(next, 0o755); err != nil {
		return err
	}
	keepNext := false
	defer func() {
		if !keepNext {
			err = errors.Join(err, os.RemoveAll(next))
		}
	}()
	if err := build(next); err != nil {
		return err
	}
	var files []string
	err = fs.WalkDir(os.DirFS(next), ".", func(name string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			files = append(files, name)
		}
		return err
	})
	if err != nil {
		return err
	}
	if err := WriteJSON(filepath.Join(next, exportFiles), files); err != nil {
		return err
	}

	if err := safePath(dest); err != nil {
		return err
	}
	info, err := os.Lstat(dest)
	if errors.Is(err, fs.ErrNotExist) {
		return rename(next, dest)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("export destination is not a directory: %s", dest)
	}
	if err := os.Chmod(next, info.Mode().Perm()); err != nil {
		return err
	}
	if err := checkExportOutput(dest); err != nil {
		return err
	}
	if err := exchange(next, dest); !errors.Is(err, errors.ErrUnsupported) {
		return err
	}
	if err := rename(dest, previous); err != nil {
		return err
	}
	if err := rename(next, dest); err != nil {
		if restoreErr := rename(previous, dest); restoreErr != nil {
			keepNext = true
			return fmt.Errorf("install export: %w; restore %s: %w", err, previous, restoreErr)
		}
		return err
	}
	return os.RemoveAll(previous)
}

func lockExportWork(work string) (*lockedfile.File, error) {
	if err := safePath(work); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(work, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(work, exportLock)
	entries, err := os.ReadDir(work)
	if err != nil {
		return nil, err
	}
	if len(entries) > 0 {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, fmt.Errorf("unrecognized export work directory %s: %w", work, err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("invalid export lock %s", path)
		}
	}
	f, err := lockedfile.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := checkExportWork(f, work); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return f, nil
}

func checkExportWork(lock *lockedfile.File, work string) error {
	contents, err := io.ReadAll(io.LimitReader(lock, int64(len(lockContents)+1)))
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(work)
	if err != nil {
		return err
	}
	if string(contents) != lockContents {
		// An interruption while initializing an otherwise empty workspace is recoverable.
		if len(entries) == 1 && strings.HasPrefix(lockContents, string(contents)) {
			_, err := lock.WriteString(lockContents[len(contents):])
			return err
		}
		return fmt.Errorf("unrecognized export lock %s", lock.Name())
	}
	for _, entry := range entries {
		if entry.Name() == exportLock || entry.IsDir() && (entry.Name() == "next" || entry.Name() == "previous") {
			continue
		}
		return fmt.Errorf("unexpected entry in export work directory: %s", filepath.Join(work, entry.Name()))
	}
	return nil
}

func recoverExport(dest, next, previous string, rename renameDirectory) error {
	if _, err := os.Lstat(previous); err == nil {
		_, err := os.Lstat(dest)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			if err := rename(previous, dest); err != nil {
				return fmt.Errorf("restore %s from %s: %w", dest, previous, err)
			}
		case err != nil:
			return err
		default:
			// Installation consumes next. If both paths exist, a different writer
			// created the destination during the fallback; keep the backup.
			if _, err := os.Lstat(next); !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("cannot recover %s while %s and %s exist", previous, dest, next)
			}
			if err := safePath(filepath.Join(dest, exportFiles)); err != nil {
				return err
			}
			if _, err := os.Stat(filepath.Join(dest, exportFiles)); err != nil {
				return fmt.Errorf("keep backup %s: %w", previous, err)
			}
			if err := checkExportOutput(dest); err != nil {
				return err
			}
			if err := os.RemoveAll(previous); err != nil {
				return err
			}
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return os.RemoveAll(next)
}

func checkExportOutput(directory string) error {
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) == 0 {
		return err
	}
	isDirectory := map[string]bool{".": true}
	for _, manifest := range []string{exportFiles, siteFiles} {
		filename := filepath.Join(directory, manifest)
		if err := safePath(filename); err != nil {
			return err
		}
		data, err := os.ReadFile(filename)
		if manifest == siteFiles && errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("use an empty or previously generated export directory: %w", err)
		}
		var files []string
		if err := json.Unmarshal(data, &files); err != nil {
			return fmt.Errorf("invalid %s: %w", manifest, err)
		}
		isDirectory[manifest] = false
		for _, name := range files {
			if !fs.ValidPath(name) || name == "." {
				return fmt.Errorf("invalid path in %s: %q", manifest, name)
			}
			isDirectory[name] = false
			for dir := path.Dir(name); dir != "."; dir = path.Dir(dir) {
				isDirectory[dir] = true
			}
		}
	}
	return fs.WalkDir(os.DirFS(directory), ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		dir, ok := isDirectory[name]
		if !ok || d.IsDir() != dir || (!dir && !d.Type().IsRegular()) {
			return fmt.Errorf("unexpected file or directory in export: %s", filepath.Join(directory, name))
		}
		return nil
	})
}
