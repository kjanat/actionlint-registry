// Package schemas bundles the public registry's JSON Schema resources.
package schemas

import (
	"embed"
	"encoding/json"
	"fmt"
	"strings"
)

const baseURL = "https://plugins.actionlint.kjanat.dev/schemas/"
const dialect = "https://json-schema.org/draft/2020-12/schema"

//go:embed *.schema.json
var files embed.FS

// Bundle returns the catalogue schema with the registry schemas embedded under
// their canonical IDs so a validator can resolve references offline.
func Bundle() (map[string]any, error) {
	entries, err := files.ReadDir(".")
	if err != nil {
		return nil, err
	}
	definitions := make(map[string]json.RawMessage, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		data, err := files.ReadFile(name)
		if err != nil {
			return nil, err
		}
		var resource struct {
			ID      string `json:"$id"`
			Dialect string `json:"$schema"`
		}
		if err := json.Unmarshal(data, &resource); err != nil {
			return nil, fmt.Errorf("schema %s: %w", name, err)
		}
		if resource.ID != baseURL+name || resource.Dialect != dialect {
			return nil, fmt.Errorf("schema %s has an unexpected ID or dialect", name)
		}
		definitions[strings.TrimSuffix(name, ".schema.json")] = data
	}
	return map[string]any{
		"$id":     baseURL + "registry.schema.json",
		"$schema": dialect,
		"$ref":    "index.schema.json",
		"$defs":   definitions,
		"title":   "actionlint plugin registry",
	}, nil
}
