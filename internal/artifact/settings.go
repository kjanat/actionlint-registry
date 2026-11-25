package artifact

import (
	"bytes"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-quickjs/go-quickjs/jsregexp"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// ConfigSetting holds a rule's options_schema or the plugin's config_schema.
// For config_schema, Category and Name are empty.
type ConfigSetting struct {
	Category string
	Name     string
	Schema   json.RawMessage
}

// ConfigSettings compiles config_schema and each options_schema in rules or descriptor.
func ConfigSettings(metadata json.RawMessage) ([]ConfigSetting, error) {
	var fields struct {
		Config     json.RawMessage `json:"config_schema"`
		Rules      json.RawMessage `json:"rules"`
		Descriptor json.RawMessage `json:"descriptor"`
	}
	if err := jsonv2.Unmarshal(metadata, &fields); err != nil {
		return nil, err
	}

	var settings []ConfigSetting
	seen := make(map[[2]string]bool)
	add := func(location string, setting ConfigSetting) error {
		key := [2]string{setting.Category, setting.Name}
		if seen[key] {
			return fmt.Errorf("%s: duplicate rule options for %q/%q", location, setting.Category, setting.Name)
		}
		if _, err := setting.document(); err != nil {
			return fmt.Errorf("%s: %w", location, err)
		}
		settings = append(settings, setting)
		seen[key] = true
		return nil
	}
	if fields.Config != nil {
		if err := add("config_schema", ConfigSetting{Schema: fields.Config}); err != nil {
			return nil, err
		}
	}

	var rules []json.RawMessage
	if jsontext.Value(fields.Rules).Kind() == '[' {
		if err := jsonv2.Unmarshal(fields.Rules, &rules); err != nil {
			return nil, err
		}
	}
	for i, raw := range append(rules, fields.Descriptor) {
		if jsontext.Value(raw).Kind() != '{' {
			continue
		}
		location := fmt.Sprintf("rules[%d]", i)
		if i == len(rules) {
			location = "descriptor"
		}
		var descriptor map[string]json.RawMessage
		if err := jsonv2.Unmarshal(raw, &descriptor); err != nil {
			return nil, fmt.Errorf("%s: %w", location, err)
		}
		options, ok := descriptor["options_schema"]
		if !ok {
			continue
		}
		setting := ConfigSetting{Schema: options}
		if err := jsonv2.Unmarshal(descriptor["name"], &setting.Name); err != nil || setting.Name == "" {
			return nil, fmt.Errorf("%s.options_schema requires a non-empty rule name", location)
		}
		if err := jsonv2.Unmarshal(descriptor["category"], &setting.Category); err != nil || setting.Category == "" {
			return nil, fmt.Errorf("%s.options_schema requires a non-empty rule category", location)
		}
		if err := add(location+".options_schema", setting); err != nil {
			return nil, err
		}
	}
	return settings, nil
}

// Resolve relative $id and $ref values against this URL until the release URL is known.
const settingBase = "https://registry.invalid/setting.schema.json"

type schemaNode struct {
	ptr  jsontext.Pointer
	obj  map[string]any
	base *url.URL
}

type settingDocument struct {
	root      any
	nodes     []schemaNode
	resources map[string]jsontext.Pointer
	locations map[jsontext.Pointer]bool
}

func (s ConfigSetting) document() (*settingDocument, error) {
	value, err := jsonschema.UnmarshalJSON(bytes.NewReader(s.Schema))
	if err != nil {
		return nil, err
	}
	d := &settingDocument{
		root:      value,
		resources: map[string]jsontext.Pointer{settingBase: ""},
		locations: make(map[jsontext.Pointer]bool),
	}
	base, _ := url.Parse(settingBase)
	if err := d.collect(value, "", base); err != nil {
		return nil, err
	}
	if err := d.references(nil); err != nil {
		return nil, err
	}
	return d, d.compile(settingBase)
}

func (d *settingDocument) collect(value any, ptr jsontext.Pointer, base *url.URL) error {
	obj, ok := value.(map[string]any)
	if !ok {
		if _, boolean := value.(bool); !boolean {
			return fmt.Errorf("schema at #%s must be an object or boolean", ptr)
		}
	}
	if dialect, ok := obj["$schema"]; ok && dialect != jsonschema.Draft2020.String() {
		return fmt.Errorf("unsupported $schema at #%s (expected %s)", ptr, jsonschema.Draft2020)
	}
	if id, ok := obj["$id"]; ok {
		ref, err := schemaURI(id)
		if err != nil || ref.Fragment != "" {
			return fmt.Errorf("invalid $id at #%s", ptr)
		}
		base = base.ResolveReference(ref)
		if previous, found := d.resources[base.String()]; found && previous != ptr {
			return fmt.Errorf("duplicate $id %q at #%s and #%s", base, previous, ptr)
		}
		d.resources[base.String()] = ptr
	}
	d.nodes = append(d.nodes, schemaNode{ptr, obj, base})
	d.locations[ptr] = true
	// Only descend into Draft 2020-12 subschemas. An $id inside a default is literal data.
	for keyword, child := range obj {
		at := ptr.AppendToken(keyword)
		switch keyword {
		case "not", "if", "then", "else", "items", "contains", "additionalProperties",
			"propertyNames", "unevaluatedProperties", "unevaluatedItems", "contentSchema":
			if err := d.collect(child, at, base); err != nil {
				return err
			}
		case "$defs", "definitions", "properties", "patternProperties", "dependentSchemas", "dependencies":
			children, _ := child.(map[string]any)
			for key, sub := range children {
				if _, names := sub.([]any); keyword == "dependencies" && names {
					continue
				}
				if err := d.collect(sub, at.AppendToken(key), base); err != nil {
					return err
				}
			}
		case "allOf", "anyOf", "oneOf", "prefixItems":
			children, _ := child.([]any)
			for i, sub := range children {
				if err := d.collect(sub, at.AppendToken(strconv.Itoa(i)), base); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// RFC 3986, sections 2 and 3. net/url accepts a raw | in a path and rewrites it as %7C.
const (
	uriChar   = `(?:[A-Za-z0-9._~!$&'()*+,;=-]|%[0-9A-Fa-f]{2})` // unreserved / sub-delims / pct-encoded
	pathChar  = `(?:` + uriChar + `|[:@])`
	queryChar = `(?:` + pathChar + `|[/?])`
	segments  = `(?:/` + pathChar + `*)*`
	ipFuture  = `[vV][A-Fa-f0-9]+\.[A-Za-z0-9._~!$&'()*+,;=:-]+`
	authority = `(?:(?:` + uriChar + `|:)*@)?(?:` + uriChar + `*|\[(?:[A-Fa-f0-9:.]+|` + ipFuture + `)\])(?::[0-9]*)?`
)

var uriReference = regexp.MustCompile(`^(?:[A-Za-z][A-Za-z0-9+.-]*:)?(?://` + authority + segments + `|/?(?:` + pathChar + `+` + segments + `)?)(?:\?` + queryChar + `*)?(?:#` + queryChar + `*)?$`)

func schemaURI(value any) (*url.URL, error) {
	s, ok := value.(string)
	if !ok || !uriReference.MatchString(s) {
		return nil, fmt.Errorf("expected a URI reference")
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(u.Host, "[") {
		host := u.Hostname()
		if !strings.HasPrefix(strings.ToLower(host), "v") {
			if ip, err := netip.ParseAddr(host); err != nil || !ip.Is6() {
				return nil, fmt.Errorf("invalid IP literal in URI reference")
			}
		}
	}
	return u, nil
}

// With a release URL, rewrite the target of each $ref and $dynamicRef. Copy the
// original fragment so JSON Pointers and dynamic anchors still select the same subschema.
func (d *settingDocument) references(published *url.URL) error {
	for _, node := range d.nodes {
		for _, keyword := range []string{"$ref", "$dynamicRef"} {
			value, ok := node.obj[keyword]
			if !ok {
				continue
			}
			ref, err := schemaURI(value)
			if err != nil {
				return fmt.Errorf("invalid %s at #%s", keyword, node.ptr)
			}
			target := node.base.ResolveReference(ref)
			fragment := target.Fragment
			target.Fragment, target.RawFragment = "", ""
			resource, found := d.resources[target.String()]
			if !found {
				return fmt.Errorf("%s at #%s references a resource outside the setting: %s", keyword, node.ptr, target)
			}
			if strings.HasPrefix(fragment, "/") && !d.locations[resource+jsontext.Pointer(fragment)] {
				return fmt.Errorf("%s at #%s does not point to a declared subschema: %s", keyword, node.ptr, ref)
			}
			if published != nil {
				replacement := publishedResource(published, resource)
				replacement.Fragment = fragment
				node.obj[keyword] = replacement.String()
			}
		}
	}
	return nil
}

func publishedResource(root *url.URL, ptr jsontext.Pointer) url.URL {
	resource := *root
	if ptr != "" {
		query := resource.Query()
		query.Set("resource", string(ptr))
		resource.RawQuery = query.Encode()
	}
	return resource
}

type ecmaRegexp interface {
	fmt.Stringer
	MatchString(string) (bool, error)
}

type schemaPattern struct {
	ecmaRegexp
	matchErr *error
}

func (p *schemaPattern) MatchString(s string) bool {
	if *p.matchErr != nil {
		return false
	}
	matched, err := p.ecmaRegexp.MatchString(s)
	if err != nil {
		*p.matchErr = fmt.Errorf("matching schema pattern %q: %w", p.String(), err)
		return false
	}
	return matched
}

// jsonschema expects a bool from MatchString. Run the compiler and any validation
// in the same callback so a match error also reaches the caller of the check.
func withSettingsCompiler(check func(*jsonschema.Compiler) error) error {
	var matchErr error
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.UseLoader(nil)
	c.UseRegexpEngine(func(pattern string) (jsonschema.Regexp, error) {
		re, err := jsregexp.Compile(pattern, "u")
		if err != nil {
			return nil, err
		}
		return &schemaPattern{re, &matchErr}, nil
	})
	err := check(c)
	if matchErr != nil {
		return matchErr
	}
	return err
}

func (d *settingDocument) compile(retrieval string) error {
	// jsonschema/v6 scans additionalItems for resources even in Draft 2020-12,
	// which removed that keyword. Pass it through to the export as literal data.
	for _, node := range d.nodes {
		if value, ok := node.obj["additionalItems"]; ok {
			delete(node.obj, "additionalItems")
			defer func() { node.obj["additionalItems"] = value }()
		}
	}
	return withSettingsCompiler(func(c *jsonschema.Compiler) error {
		if err := c.AddResource(retrieval, d.root); err != nil {
			return err
		}
		// Compiling the root alone skips unused entries in $defs.
		for _, node := range d.nodes {
			loc := url.URL{Fragment: string(node.ptr)}
			if _, err := c.Compile(retrieval + loc.String()); err != nil {
				return err
			}
		}
		return nil
	})
}

// Rebase sets the root $id to the setting URL. Nested resources use the same URL
// with their JSON Pointer in the resource query parameter.
func (s ConfigSetting) Rebase(id string) (json.RawMessage, error) {
	d, err := s.document()
	if err != nil {
		return nil, err
	}
	root, err := url.Parse(id)
	if err != nil || !root.IsAbs() || root.Fragment != "" {
		return nil, fmt.Errorf("invalid published setting URL %q", id)
	}
	if err := d.references(root); err != nil {
		return nil, err
	}
	for _, node := range d.nodes {
		if _, exists := node.obj["$id"]; node.obj != nil && (node.ptr == "" || exists) {
			resource := publishedResource(root, node.ptr)
			node.obj["$id"] = resource.String()
		}
	}
	if obj, ok := d.root.(map[string]any); ok {
		obj["$schema"] = jsonschema.Draft2020.String()
	}
	if err := d.compile(id); err != nil {
		return nil, err
	}
	return json.Marshal(d.root)
}
