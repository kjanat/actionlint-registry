package registry

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"registry.actionlint.kjanat.dev/internal/compatibility"
	"registry.actionlint.kjanat.dev/schemas"
)

func Find(index Index, repository, tag string) (Entry, error) {
	for _, e := range index.Entries {
		legacy := e.IdentityVersion == 0 && strings.EqualFold(e.Submission.Provider+"/"+e.Submission.Repository, repository)
		if (legacy || strings.EqualFold(e.Name(), repository)) && e.Submission.Tag == tag {
			return e, nil
		}
	}
	return Entry{}, fmt.Errorf("no accepted version %s@%s", repository, tag)
}

func Resolve(index Index, repository, tag string) (string, error) {
	entry, err := Find(index, repository, tag)
	if err != nil {
		return "", err
	}
	return entry.PinnedURL(), nil
}

type Catalog struct {
	SchemaVersion int             `json:"schema_version"`
	Source        string          `json:"source,omitempty"`
	Statuses      string          `json:"statuses,omitempty"`
	Plugins       []CatalogPlugin `json:"plugins"`
}
type CatalogPlugin struct {
	Name     string   `json:"name"`
	PluginID string   `json:"plugin_id"`
	Manifest string   `json:"manifest"`
	Aliases  []string `json:"aliases,omitempty"`
}
type CompatibilityLink struct {
	Host    compatibility.Host `json:"host"`
	Policy  string             `json:"policy"`
	Outcome string             `json:"outcome"`
	Report  string             `json:"report"`
}

type VersionLink struct {
	Compatibility []CompatibilityLink `json:"compatibility"`
	Version       string              `json:"version"`
	Record        string              `json:"record"`
	Imports       []string            `json:"imports,omitzero"`
	Exports       []string            `json:"exports,omitzero"`
}

func interfaceFacts(entry Entry, observations []compatibility.Evidence) (imports, exports []string) {
	listed := map[string]bool{}
	for _, item := range observations {
		listed[item.Report.ArtifactSHA256] = listed[item.Report.ArtifactSHA256] || item.Report.HasInterfaces()
	}
	for _, found := range listed {
		if !found {
			return nil, nil
		}
	}
	if entry.Submission.IsOCI() {
		if len(entry.OCIPrimaryLayers) == 0 {
			return nil, nil
		}
		for _, layer := range entry.OCIPrimaryLayers {
			if !listed[layer] {
				return nil, nil
			}
		}
	}
	for _, item := range observations {
		if !item.Report.HasInterfaces() {
			continue
		}
		if imports == nil {
			imports, exports = item.Report.Imports, item.Report.Exports
			continue
		}
		if !slices.Equal(imports, item.Report.Imports) || !slices.Equal(exports, item.Report.Exports) {
			return nil, nil
		}
	}
	return imports, exports
}

type PluginManifest struct {
	Plugin   Plugin        `json:"plugin"`
	Versions []VersionLink `json:"versions"`
}

func Export(index Index, directory string, statuses []ReleaseStatus, aliases *Aliases, evidence ...compatibility.Evidence) error {
	return export(index, directory, statuses, nil, aliases, evidence...)
}

func export(index Index, directory string, statuses []ReleaseStatus, downloads *DownloadSnapshot, aliases *Aliases, evidence ...compatibility.Evidence) error {
	return replaceExport(directory, func(staging string) error {
		return writeExport(index, staging, statuses, downloads, aliases, evidence...)
	})
}

func writeExport(index Index, directory string, statuses []ReleaseStatus, downloads *DownloadSnapshot, aliases *Aliases, evidence ...compatibility.Evidence) error {
	schema, err := schemas.Bundle()
	if err != nil {
		return err
	}
	if err := schemas.CopyResources(filepath.Join(directory, "schemas")); err != nil {
		return err
	}
	if aliases != nil {
		if err := aliases.Validate(index); err != nil {
			return err
		}
	}
	for _, status := range statuses {
		if _, err := status.validate(index); err != nil {
			return err
		}
	}
	observations := map[string][]CompatibilityLink{}
	releases := map[string][]compatibility.Evidence{}
	for _, item := range evidence {
		if err := item.Validate(); err != nil {
			return err
		}
		if err := acceptedRelease(index, item); err != nil {
			return fmt.Errorf("cannot export evidence: %w", err)
		}
		name, err := evidenceName(item)
		if err != nil {
			return err
		}
		path := "compatibility/" + item.Release() + "/" + name
		if err = WriteJSON(filepath.Join(directory, filepath.FromSlash(path)), item); err != nil {
			return err
		}
		observations[item.Release()] = append(observations[item.Release()], CompatibilityLink{Host: item.Report.Host, Policy: item.Report.Policy, Outcome: item.Report.Outcome, Report: "../../" + path})
		releases[item.Release()] = append(releases[item.Release()], item)
	}
	catalog := Catalog{SchemaVersion: 1, Statuses: "statuses.json", Plugins: []CatalogPlugin{}}
	manifests := map[string]PluginManifest{}
	for _, entry := range index.Entries {
		id := entry.PluginKey()
		manifest, ok := manifests[id]
		if !ok {
			manifest = PluginManifest{Plugin: pluginFor(entry), Versions: []VersionLink{}}
			plugin := CatalogPlugin{Name: entry.Name(), PluginID: entry.PluginID(), Manifest: "plugins/" + id + "/index.json"}
			if aliases != nil {
				plugin.Aliases = aliases.For(plugin.Name)
			}
			catalog.Plugins = append(catalog.Plugins, plugin)
		}
		filename := key(entry.Submission.Tag) + ".json"
		link := VersionLink{Version: entry.Submission.Tag, Record: "versions/" + filename, Compatibility: append([]CompatibilityLink{}, observations[entry.Submission.Digest()]...)}
		if entry.Submission.Kind == "component" {
			link.Imports, link.Exports = interfaceFacts(entry, releases[entry.Submission.Digest()])
		}
		manifest.Versions = append(manifest.Versions, link)
		manifests[id] = manifest
		if err := WriteJSON(filepath.Join(directory, "plugins", id, "versions", filename), entry); err != nil {
			return err
		}
	}
	slices.SortFunc(catalog.Plugins, func(a, b CatalogPlugin) int { return strings.Compare(a.Name, b.Name) })
	for id, manifest := range manifests {
		if err := WriteJSON(filepath.Join(directory, "plugins", id, "index.json"), manifest); err != nil {
			return err
		}
	}
	if err := writeCatalog(directory, catalog); err != nil {
		return err
	}
	if err := WriteJSON(filepath.Join(directory, "statuses.json"), StatusSnapshot{SchemaVersion: 1, Releases: append([]ReleaseStatus{}, statuses...)}); err != nil {
		return err
	}
	if downloads != nil {
		if err := WriteJSON(filepath.Join(directory, "downloads.json"), downloads); err != nil {
			return err
		}
	}
	if err := WriteJSON(filepath.Join(directory, "schemas", "registry.schema.json"), schema); err != nil {
		return err
	}
	return exportConfigSchemas(index, directory, statuses, os.Stderr)
}

func writeCatalog(directory string, catalog Catalog) error {
	slices.SortFunc(catalog.Plugins, func(a, b CatalogPlugin) int { return strings.Compare(a.Name, b.Name) })
	return WriteJSON(filepath.Join(directory, "index.json"), catalog)
}
