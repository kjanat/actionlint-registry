package artifact

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestInspectRejectsInvalidSettingsSchemas(t *testing.T) {
	for name, fields := range map[string]string{
		".NET atomic group":       `"config_schema":{"pattern":"(?>abc)"}`,
		".NET comment":            `"config_schema":{"pattern":"(?#comment)abc"}`,
		".NET inline flag":        `"config_schema":{"pattern":"(?i)foo"}`,
		"unescaped pipe in $id":   `"config_schema":{"$id":"a|none"}`,
		"unescaped braces in $id": `"config_schema":{"$id":"a{}"}`,
		"unescaped pipe in $ref":  `"config_schema":{"$defs":{"child|":{"type":"string"}},"$ref":"#/$defs/child|"}`,
		"Go named capture":        `"config_schema":{"pattern":"(?P<bad>abc)"}`,
		"numeric type keyword":    `"config_schema":{"type":123}`,
		"unknown type in $defs":   `"config_schema":{"$defs":{"unused":{"type":"typo"}}}`,
		"unresolved pointer":      `"config_schema":{"$ref":"#/$defs/missing"}`,
		"unresolved anchor":       `"config_schema":{"$defs":{"unused":{"$ref":"#missing"}}}`,
		"external reference":      `"config_schema":{"$ref":"https://example.com/elsewhere"}`,
		"local file":              `"config_schema":{"$ref":"file:///tmp/elsewhere.json"}`,
		"null config_schema":      `"config_schema":null`,
		"array as options_schema": `"rules":[{"name":"x","category":"y","options_schema":[] }]`,
		"missing rule name":       `"rules":[{"category":"y","options_schema":true}]`,
		"duplicate options":       `"rules":[{"name":"x","category":"y","options_schema":true},{"name":"x","category":"y","options_schema":false}]`,
		"legacy dialect":          `"config_schema":{"$schema":"http://json-schema.org/draft-07/schema#"}`,
		"nested dialect":          `"config_schema":{"$defs":{"nested":{"$id":"nested","$schema":"http://json-schema.org/draft-07/schema#"}}}`,
		"duplicate resource":      `"config_schema":{"$defs":{"a":{"$id":"one"},"b":{"$id":"one"}}}`,
		"fragment id":             `"config_schema":{"$id":"other#notallowed"}`,
		"$ref into default":       `"config_schema":{"default":{"type":"string"},"$ref":"#/default"}`,
	} {
		t.Run(name, func(t *testing.T) {
			data := strings.TrimSuffix(string(declarationJSON("core")), "}") + "," + fields + "}"
			if _, err := inspectBytes(t, wasm("core", []byte(data))); err == nil || !strings.Contains(err.Error(), "plugin settings") {
				t.Fatalf("Inspect error = %v, want a plugin settings error", err)
			}
		})
	}
}

func TestConfigSettingsRejectsDuplicateRuleInRulesAndDescriptor(t *testing.T) {
	const metadata = `{"rules":[{"name":"x","category":"y","options_schema":true}],"descriptor":{"name":"x","category":"y","options_schema":false}}`
	if _, err := ConfigSettings([]byte(metadata)); err == nil || !strings.Contains(err.Error(), "duplicate rule") {
		t.Fatalf("ConfigSettings error = %v, want a duplicate rule error", err)
	}
}

func TestRebaseBooleanSettingsSchemas(t *testing.T) {
	settings, err := ConfigSettings([]byte(`{"config_schema":false,"descriptor":{"name":"x","category":"y","options_schema":true}}`))
	if err != nil || len(settings) != 2 || settings[1].Name != "x" {
		t.Fatalf("valid boolean settings: %v %v", settings, err)
	}
	for _, setting := range settings {
		published, err := setting.Rebase("https://registry.example/settings.json")
		if err != nil || !bytes.Equal(published, setting.Schema) {
			t.Fatalf("published boolean: %s, %v", published, err)
		}
	}
}

func TestConfigSettingsSkipsRulesWithoutOptionsSchema(t *testing.T) {
	for _, extension := range []string{`"descriptor":"opaque","rules":["opaque"]`, `"rules":{"future":true}`, `"descriptor":{"name":{"future":true}}`} {
		settings, err := ConfigSettings([]byte(`{"config_schema":true,` + extension + `}`))
		if err != nil || len(settings) != 1 {
			t.Fatalf("metadata %s: got %d settings, err = %v", extension, len(settings), err)
		}
	}
}

func TestConfigSchemaAcceptsLookaheadAndBackreferences(t *testing.T) {
	settings, err := ConfigSettings([]byte(`{"config_schema":{"pattern":"^(?=v[0-9])v(.*)\\1$"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := settings[0].Rebase("https://registry.example/settings.json"); err != nil {
		t.Fatal(err)
	}
}

func TestRebaseTwoReleasesWithTheSameSchemaID(t *testing.T) {
	const schema = `{
		"$id":"https://publisher.example/root",
		"$defs":{
			"leaf":{"$id":"schemas/leaf","$dynamicAnchor":"option","type":"integer","minimum":9007199254740993,"const":%d},
			"alias":{"$id":"schemas/alias","$dynamicRef":"leaf#option"}
		},
		"$ref":"schemas/alias",
		"default":{"$id":"literal","$ref":"untouched"}
	}`
	const base = "https://registry.example/plugins/demo/%d.schema.json"
	c := jsonschema.NewCompiler()
	c.UseLoader(nil)
	for _, n := range []int{1, 2} {
		number := 9007199254740992 + int64(n)
		setting := ConfigSetting{Schema: json.RawMessage(fmt.Sprintf(schema, number))}
		id := fmt.Sprintf(base, n)
		raw, err := setting.Rebase(id)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(raw, []byte(`"minimum":9007199254740993`)) ||
			!bytes.Contains(raw, []byte(`"default":{"$id":"literal","$ref":"untouched"}`)) {
			t.Fatalf("release %d changed minimum or default: %s", n, raw)
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		if err := c.AddResource(id, doc); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range []int{2, 1} {
		s, err := c.Compile(fmt.Sprintf(base, n))
		if err != nil {
			t.Fatal(err)
		}
		var accepted []int
		for _, value := range []int{1, 2} {
			if s.Validate(json.Number(fmt.Sprint(9007199254740992+int64(value)))) == nil {
				accepted = append(accepted, value)
			}
		}
		if !slices.Equal(accepted, []int{n}) {
			t.Fatalf("release %d accepted %v", n, accepted)
		}
	}
}
