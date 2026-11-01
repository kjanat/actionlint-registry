package registry

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestDistributionProtocols(t *testing.T) {
	legacy := sampleSubmission()
	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(`"artifact"`)) {
		t.Fatal("legacy protocol changed", string(data))
	}
	parsed, err := ParseSubmission(data)
	if err != nil || parsed != legacy {
		t.Fatal("legacy roundtrip", parsed, err)
	}
	for _, distribution := range []string{`{"type":"release-asset","name":"plugin.json","sha256":"` + strings.Repeat("a", 64) + `"}`, `{"type":"oci","reference":"oci://registry.example/plugins/example@sha256:` + strings.Repeat("b", 64) + `"}`} {
		wire := `{"schema_version":2,"provider":"github","repository":"publisher/plugin","tag":"v1.0.0","kind":"manifest","artifact":` + distribution + `}`
		submission, err := ParseSubmission([]byte(wire))
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(submission)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(encoded, []byte(`"asset"`)) || bytes.Count(encoded, []byte(`"sha256"`)) > 1 {
			t.Fatal("v2 leaked v1 fields", string(encoded))
		}
		for _, suffix := range []string{`,"asset":""`, `,"sha256":null`, `,"asset":"plugin.wasm"`} {
			if _, err := ParseSubmission([]byte(strings.TrimSuffix(wire, "}") + suffix + "}")); err == nil {
				t.Fatal("mixed protocol accepted", suffix)
			}
		}
	}
	for _, reference := range []string{"oci://registry.example/repo:latest", "oci://registry.example/repo@sha256:" + strings.Repeat("A", 64), "oci://user@registry.example/repo@sha256:" + strings.Repeat("a", 64), "oci://Registry.example/repo@sha256:" + strings.Repeat("a", 64), "oci://registry.example:0/repo@sha256:" + strings.Repeat("a", 64), "oci://registry.example:65536/repo@sha256:" + strings.Repeat("a", 64), "oci://registry.example:/repo@sha256:" + strings.Repeat("a", 64)} {
		if _, err := OCIReference(reference); err == nil {
			t.Fatal("invalid reference accepted", reference)
		}
	}
	for _, port := range []string{"443", "5000", "65535", "00443"} {
		if _, err := OCIReference("oci://registry.example:" + port + "/repo@sha256:" + strings.Repeat("a", 64)); err != nil {
			t.Fatal("valid explicit public HTTPS port rejected", port, err)
		}
	}
	if _, err := OCIReference("oci://registry--cache.example/repo@sha256:" + strings.Repeat("a", 64)); err != nil {
		t.Fatal("valid DNS hostname rejected", err)
	}
	if _, err := OCIReference("oci://registry..example/repo@sha256:" + strings.Repeat("a", 64)); err == nil {
		t.Fatal("empty DNS label accepted")
	}
	legacyManifest := sampleSubmission()
	legacyManifest.Kind, legacyManifest.Asset = "manifest", "plugin.json"
	if err := legacyManifest.Validate(); err == nil {
		t.Fatal("v1 wire contract broadened to process manifests")
	}
	for _, distribution := range []string{
		`{"type":"oci","reference":"oci://registry.example/repo@sha256:` + strings.Repeat("a", 64) + `","name":null}`,
		`{"type":"oci","reference":"oci://registry.example/repo@sha256:` + strings.Repeat("a", 64) + `","sha256":null}`,
		`{"type":"release-asset","name":"plugin.json","sha256":"` + strings.Repeat("a", 64) + `","reference":null}`,
	} {
		wire := `{"schema_version":2,"provider":"github","repository":"publisher/plugin","tag":"v1.0.0","kind":"manifest","artifact":` + distribution + `}`
		if _, err := ParseSubmission([]byte(wire)); err == nil {
			t.Fatal("wrong distribution branch field accepted", distribution)
		}
	}
}
