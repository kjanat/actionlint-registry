package registry

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
)

const exportFiles = ".registry-export-files.json"
const siteFiles = ".registry-site-files.json"

func replaceExport(directory string, build func(string) error) error {
	dest, err := filepath.Abs(directory)
	if err != nil {
		return err
	}
	if err := safePath(dest); err != nil {
		return err
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
	work, err := os.MkdirTemp(parent, ".registry-export-*")
	if err != nil {
		return err
	}
	// RemoveAll would also delete the backup if rollback fails.
	defer func() { _ = os.Remove(work) }()
	next := filepath.Join(work, "next")
	if err := os.Mkdir(next, 0o755); err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(next) }()
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

	info, err := os.Lstat(dest)
	if errors.Is(err, fs.ErrNotExist) {
		return os.Rename(next, dest)
	}
	if err != nil {
		return err
	}
	if err := os.Chmod(next, info.Mode().Perm()); err != nil {
		return err
	}
	if err := checkExportOutput(dest); err != nil {
		return err
	}
	previous := filepath.Join(work, "previous")
	if err := os.Rename(dest, previous); err != nil {
		return err
	}
	if err := os.Rename(next, dest); err != nil {
		if restoreErr := os.Rename(previous, dest); restoreErr != nil {
			return fmt.Errorf("replace export directory: %w (could not restore %s: %v)", err, previous, restoreErr)
		}
		return err
	}
	return os.RemoveAll(previous)
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
