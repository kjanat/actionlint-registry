package artifact

import (
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"testing"
)

func TestRebaseSubschemaKeywords(t *testing.T) {
	const published = "https://registry.example/v1/options.json"
	const child = `{
		"$id":"options/", "$anchor":"settings", "$ref":"choice#leaf",
		"$defs":{"a~/b":{"$id":"choice","$anchor":"leaf","const":"accepted"}}
	}`
	for _, group := range []struct {
		keywords []string
		value    string
		suffix   string
	}{
		{[]string{"not", "if", "then", "else", "items", "contains", "additionalProperties",
			"propertyNames", "unevaluatedProperties", "unevaluatedItems", "contentSchema"}, "%s", ""},
		{[]string{"$defs", "definitions", "properties", "patternProperties", "dependentSchemas", "dependencies"},
			`{"key~/part":%s}`, "/key~0~1part"},
		{[]string{"allOf", "anyOf", "oneOf", "prefixItems"}, `[true,%s]`, "/1"},
	} {
		for _, keyword := range group.keywords {
			t.Run(keyword, func(t *testing.T) {
				pointer := "/" + keyword + group.suffix
				setting := func(ref, schema string) ConfigSetting {
					raw := fmt.Sprintf(`{"$ref":%q,%q:%s}`, ref, keyword, fmt.Sprintf(group.value, schema))
					return ConfigSetting{Schema: json.RawMessage(raw)}
				}

				doc, err := setting("options/#settings", child).Rebase(published)
				if err != nil {
					t.Fatal(err)
				}
				childID := published + "?resource=" + url.QueryEscape(pointer)
				leafID := published + "?resource=" + url.QueryEscape(pointer+"/$defs/a~0~1b")
				wantChild := fmt.Sprintf(`{
					"$id":%q, "$anchor":"settings", "$ref":%q,
					"$defs":{"a~/b":{"$id":%q,"$anchor":"leaf","const":"accepted"}}
				}`, childID, leafID+"#leaf", leafID)
				want := fmt.Sprintf(`{"$id":%q,"$schema":"https://json-schema.org/draft/2020-12/schema","$ref":%q,%q:%s}`,
					published, childID+"#settings", keyword, fmt.Sprintf(group.value, wantChild))
				checkSchemaJSON(t, doc, []byte(want))

				// A pointer can target a boolean at the same position.
				doc, err = setting("#"+pointer, "false").Rebase(published)
				if err != nil {
					t.Fatal(err)
				}
				want = fmt.Sprintf(`{"$id":%q,"$schema":"https://json-schema.org/draft/2020-12/schema","$ref":%q,%q:%s}`,
					published, published+"#"+pointer, keyword, fmt.Sprintf(group.value, "false"))
				checkSchemaJSON(t, doc, []byte(want))
			})
		}
	}
}

func TestRebaseLeavesSchemaLikeDataUntouched(t *testing.T) {
	const literal = `{"$id":"literal","$schema":"https://publisher.example/extension","$ref":"missing","$dynamicRef":"#unknown","type":123}`
	const published = "https://registry.example/v1/options.json"
	fields := fmt.Sprintf(`"default":%[1]s,"const":%[1]s,"enum":[%[1]s],"examples":[%[1]s],"x-plugin":%[1]s,
		"$defs":{"nested":{"additionalItems":%[1]s}},"dependencies":{"path":["$id","$ref"]}`, literal)
	s := ConfigSetting{Schema: json.RawMessage(`{` + fields + `}`)}
	doc, err := s.Rebase(published)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf(`{"$id":%q,"$schema":"https://json-schema.org/draft/2020-12/schema",%s}`, published, fields)
	checkSchemaJSON(t, doc, []byte(want))
}

func TestConfigSettingsRejectsReferencesIntoAdditionalItems(t *testing.T) {
	for _, ref := range []string{"#/additionalItems", "#literal"} {
		raw := fmt.Sprintf(`{"config_schema":{"additionalItems":{"$anchor":"literal"},"$ref":%q}}`, ref)
		if _, err := ConfigSettings([]byte(raw)); err == nil {
			t.Errorf("ConfigSettings accepted a reference into additionalItems: %s", ref)
		}
	}
}

func TestFailedCompileLeavesAdditionalItemsInDocument(t *testing.T) {
	root := map[string]any{"type": "invalid", "additionalItems": false}
	doc := settingDocument{root: root, nodes: []schemaNode{{obj: root}}}
	if err := doc.compile(settingBase); err == nil {
		t.Fatal("compile accepted an unknown type")
	}
	if value, ok := root["additionalItems"]; !ok || value != false {
		t.Fatal("compile changed additionalItems after rejecting the schema")
	}
}

func checkSchemaJSON(t *testing.T, got, want []byte) {
	t.Helper()
	var a, b any
	if err := json.Unmarshal(got, &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(want, &b); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("schema = %s\nwant %s", got, want)
	}
}
