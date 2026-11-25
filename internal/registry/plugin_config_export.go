package registry

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"registry.actionlint.kjanat.dev/internal/artifact"
)

const (
	configSchemaOrigin = "https://plugins.actionlint.kjanat.dev/"
	configSchemaRoot   = "schemas/plugin-config.schema.json"
	configCatalogPath  = "schemas/plugin-config.catalog.json"
)

// The root, plugin, and version documents are directories of schema references.
// A consumer applies a specific setting, never all plugin releases at once.
type configSchemaIndex struct {
	Dialect string                        `json:"$schema,omitempty"`
	ID      string                        `json:"$id,omitempty"`
	Title   string                        `json:"title,omitempty"`
	Defs    map[string]*configSchemaIndex `json:"$defs,omitzero"`
	Ref     string                        `json:"$ref,omitempty"`
}

func configIndex(path, title string) *configSchemaIndex {
	return &configSchemaIndex{Dialect: "https://json-schema.org/draft/2020-12/schema", ID: configSchemaOrigin + path, Title: title, Defs: map[string]*configSchemaIndex{}}
}

func (index *configSchemaIndex) group(name string) *configSchemaIndex {
	if index.Defs[name] == nil {
		index.Defs[name] = &configSchemaIndex{Defs: map[string]*configSchemaIndex{}}
	}
	return index.Defs[name]
}

type configCatalogPlugin struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	URL         string            `json:"url"`
	Versions    map[string]string `json:"versions"`
}

type configCatalog struct {
	Schema  string                `json:"$schema"`
	Version int                   `json:"version"`
	Schemas []configCatalogPlugin `json:"schemas"`
}

func exportConfigSchemas(index Index, directory string, statuses []ReleaseStatus, warnings io.Writer) error {
	root := configIndex(configSchemaRoot, "Plugin settings by plugin selector")
	catalog := configCatalog{Schema: "https://www.schemastore.org/schema-catalog.json", Version: 1, Schemas: []configCatalogPlugin{}}
	plugins := map[string][]Entry{}
	for _, entry := range index.Entries {
		plugins[entry.Name()] = append(plugins[entry.Name()], entry)
	}
	for _, name := range slices.Sorted(maps.Keys(plugins)) {
		releases := plugins[name]
		slices.SortFunc(releases, func(a, b Entry) int {
			if byDate := b.PublishedAt.Compare(a.PublishedAt); byDate != 0 {
				return byDate
			}
			return strings.Compare(b.Submission.Tag, a.Submission.Tag)
		})
		prefix := "schemas/plugin-config/" + releases[0].PluginKey() + "/"
		pluginPath := prefix + "index.schema.json"
		plugin := configIndex(pluginPath, name+" settings by release tag")
		catalogPlugin := configCatalogPlugin{Name: name, Versions: map[string]string{}}
		for _, entry := range releases {
			tag := entry.Submission.Tag
			metadata := entry.metadata()
			releasePrefix := prefix + key(tag) + "/"
			releasePath := releasePrefix + "index.schema.json"
			release := configIndex(releasePath, name+"@"+tag+" settings")
			settings, err := releaseSettings(metadata, releasePrefix, release)
			if err != nil {
				if _, err := fmt.Fprintf(warnings, "Skipping configuration schema for %s@%s: %v\n", name, tag, err); err != nil {
					return err
				}
				continue
			}
			if len(settings) == 0 {
				continue
			}
			for path, schema := range settings {
				if err := WriteJSON(filepath.Join(directory, filepath.FromSlash(path)), schema); err != nil {
					return err
				}
			}
			if err := WriteJSON(filepath.Join(directory, filepath.FromSlash(releasePath)), release); err != nil {
				return err
			}
			plugin.Defs[tag] = &configSchemaIndex{Ref: release.ID}
			catalogPlugin.Versions[tag] = release.ID
			status := StatusFor(entry, statuses)
			if catalogPlugin.URL == "" && (status == nil || status.Status == StatusActive) {
				catalogPlugin.URL = release.ID
				var info struct {
					Description string `json:"description"`
				}
				if err := json.Unmarshal(metadata, &info); err != nil {
					return err
				}
				catalogPlugin.Description = info.Description
			}
		}
		if len(plugin.Defs) != 0 {
			if err := WriteJSON(filepath.Join(directory, filepath.FromSlash(pluginPath)), plugin); err != nil {
				return err
			}
			root.Defs[name] = &configSchemaIndex{Ref: plugin.ID}
		}
		if catalogPlugin.URL != "" {
			catalog.Schemas = append(catalog.Schemas, catalogPlugin)
		}
	}
	if err := WriteJSON(filepath.Join(directory, configSchemaRoot), root); err != nil {
		return err
	}
	return WriteJSON(filepath.Join(directory, configCatalogPath), catalog)
}

// Prepare the whole release before advertising any settings from it.
func releaseSettings(metadata json.RawMessage, prefix string, release *configSchemaIndex) (map[string]json.RawMessage, error) {
	settings, err := artifact.ConfigSettings(metadata)
	if err != nil {
		return nil, err
	}
	files := make(map[string]json.RawMessage, len(settings))
	for _, setting := range settings {
		group, name, path := release, "config", prefix+"config.schema.json"
		if setting.Category != "" {
			group = release.group("rules").group(setting.Category)
			name = setting.Name
			path = prefix + "rules/" + key(setting.Category) + "/" + key(name) + ".schema.json"
		}
		id := configSchemaOrigin + path
		schema, err := setting.Rebase(id)
		if err != nil {
			return nil, err
		}
		files[path] = schema
		group.Defs[name] = &configSchemaIndex{Ref: id}
	}
	return files, nil
}
