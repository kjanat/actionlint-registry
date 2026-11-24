package validation

import (
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"actionlint.kjanat.dev/v2/internal/development/tests/testutil/wasmcomponent"
	"actionlint.kjanat.dev/v2/internal/plugins/pluginexecution/component"
)

const componentContractDigest = "287f569cb6587a23f2195f9d8398f370c32a2b21deed1fac42f3b56fd03c7c23"
const scriptContractDigest = "c20d7e9e516166576fdf19bfd86e0843838179b12ad55350c33db8d04c2eaa9b"
const runnerContractDigest = "2a995ebe267d4d5df5664c0f6f48b40cc770116ef9375935f26f3a648652df9f"

// ShellCheck vendors the same analyzer types with older documentation comments.
// Both source digests must reach type validation, including incompatible exports.
func TestAnalyzerCompatibilityUsesExportedTypes(t *testing.T) {
	for _, digest := range []string{componentContractDigest, "a0096f562ab3da46b30d0f025ad1c6ed0d46e5b7ea1a53660b3214e3270fcbee"} {
		metadata := strings.Replace(componentMetadata, componentContractDigest, digest, 1)
		result, err := Validate(t.Context(), testAsOf, packagedFixture(t, "component-no-sudo", metadata))
		if err != nil {
			t.Fatal(err)
		}
		if result.Contract != component.AnalyzerInterface+"#sha256="+digest {
			t.Fatalf("changed declared source identity: %s", result.Contract)
		}
		_, err = Validate(t.Context(), testAsOf, packagedFixture(t, "component-wrong-record", metadata))
		if err == nil || errors.Is(err, ErrUnsupportedContract) {
			t.Fatalf("wrong types must fail runtime validation: %v", err)
		}
	}
	for _, invalid := range []string{"", "invalid", strings.Repeat("A", 64), strings.Repeat("0", 63)} {
		metadata := strings.Replace(componentMetadata, componentContractDigest, invalid, 1)
		if _, err := Validate(t.Context(), testAsOf, packagedFixture(t, "component-no-sudo", metadata)); err == nil {
			t.Fatal("accepted malformed digest")
		}
	}
}

func TestComponentInterfaceVersions(t *testing.T) {
	for fixture, exports := range map[string][]string{
		"component-no-sudo":               {component.AnalyzerInterface},
		"component-managed-no-sudo":       {component.AnalyzerInterface, component.ToolIntegrationInterface},
		"component-script":                {component.ScriptEngineInterface},
		"component-script-0.3.0":          {component.ScriptEngine03Interface},
		"component-template-script-0.3.0": {component.ScriptEngine03Interface, component.TemplateEffects03Interface},
		"component-runners":               {component.RunnerInterface},
		"component-runners-0.3.0":         {component.Runner03Interface},
	} {
		data, err := os.ReadFile(hostFixture(t, fixture))
		if err != nil {
			t.Fatal(err)
		}
		roles, err := admitComponent(t.Context(), data)
		if err != nil || !slices.Equal(slices.Sorted(slices.Values(roles.Exports())), slices.Sorted(slices.Values(exports))) {
			t.Fatalf("%s: roles %v, %v; want %v", fixture, roles.Exports(), err, exports)
		}
	}
	if roles, err := admitComponent(t.Context(), component.BuiltinCommitishArtifact().Bytes); err != nil || roles.ReferenceResolver != component.ReferenceResolverInterface {
		t.Fatalf("reference resolver: roles %+v, %v", roles, err)
	}
	for _, exports := range [][]string{
		{"kjanat:actionlint/analyzer@0.1.0"},
		{"kjanat:actionlint/script-engine@0.1.0"},
		{"kjanat:actionlint/runner-provider@0.4.0"},
		{"example:future/analyzer@2.0.0"},
		{component.AnalyzerInterface, "kjanat:actionlint/tool-integration@0.1.0"},
		{component.ScriptEngine03Interface, "kjanat:actionlint/template-effects@0.1.0"},
		{component.AnalyzerInterface, "kjanat:actionlint/runner-provider@0.4.0"},
	} {
		if _, err := admitComponent(t.Context(), wasmcomponent.Build(nil, exports, nil)); !errors.Is(err, ErrUnsupportedContract) {
			t.Fatalf("%v: want unsupported, got %v", exports, err)
		}
	}
}

func interfaceMetadata(iface string) string {
	return strings.Replace(componentMetadata, `"interface":"`+component.AnalyzerInterface+`"`, `"interface":"`+iface+`"`, 1)
}

func TestDeclaredInterfaceMustMatchExports(t *testing.T) {
	for _, declared := range []string{"kjanat:actionlint/analyzer@0.1.0", "kjanat:actionlint/analyzer@0.3.0", component.Runner03Interface} {
		_, err := Validate(t.Context(), testAsOf, packagedFixture(t, "component-no-sudo", interfaceMetadata(declared)))
		if err == nil || errors.Is(err, ErrUnsupportedContract) || !strings.Contains(err.Error(), declared) {
			t.Fatalf("%s declared on an analyzer@0.2.0 export: want a failed check, got %v", declared, err)
		}
	}
	older := "kjanat:actionlint/analyzer@0.1.0"
	built := wasmcomponent.Build(nil, []string{older}, nil)
	if _, err := Validate(t.Context(), testAsOf, appendFixtureMetadata(t, built, interfaceMetadata(older))); !errors.Is(err, ErrUnsupportedContract) {
		t.Fatalf("an exported interface this host does not load must be unsupported, got %v", err)
	}
	if _, err := Validate(t.Context(), testAsOf, appendFixtureMetadata(t, built, componentMetadata)); !errors.Is(err, ErrUnsupportedContract) {
		t.Fatalf("an older export under a current declaration must be unsupported, got %v", err)
	}
}

func TestDeclaredSecondaryRole(t *testing.T) {
	template := strings.Replace(templateMetadata03, `"interface":"`+component.ScriptEngine03Interface+`"`, `"interface":"`+component.TemplateEffects03Interface+`"`, 1)
	if _, err := Validate(t.Context(), testAsOf, packagedFixture(t, "component-template-script-0.3.0", template)); err == nil || errors.Is(err, ErrUnsupportedContract) || !strings.Contains(err.Error(), "script engine static metadata") {
		t.Errorf("template-effects declared on a script engine: want the host's metadata rejection as a failure, got %v", err)
	}
	if _, err := Validate(t.Context(), testAsOf, packagedFixture(t, "component-managed-no-sudo", interfaceMetadata(component.ToolIntegrationInterface))); errors.Is(err, ErrUnsupportedContract) {
		t.Errorf("tool-integration declared on an analyzer that exports it: want its role checks, got %v", err)
	}
}

func TestUnprovidedSecondaryExportIsUnsupported(t *testing.T) {
	future := "kjanat:actionlint/runner-provider@0.4.0"
	for name, path := range map[string]string{
		"declared analyzer": appendFixtureMetadata(t, wasmcomponent.Build(nil, []string{component.AnalyzerInterface, future}, nil), componentMetadata),
		"declared future":   appendFixtureMetadata(t, wasmcomponent.Build(nil, []string{future}, nil), interfaceMetadata(future)),
	} {
		if _, err := Validate(t.Context(), testAsOf, path); !errors.Is(err, ErrUnsupportedContract) || !strings.Contains(err.Error(), future) {
			t.Errorf("%s: want unsupported naming %s, got %v", name, future, err)
		}
	}
}

func TestOpenReadsComponentInterfaces(t *testing.T) {
	opened, err := Open(t.Context(), packagedFixture(t, "component-no-sudo", componentMetadata))
	if err != nil {
		t.Fatal(err)
	}
	if opened.Interfaces == nil || !slices.Equal(opened.Interfaces.Exports, []string{component.AnalyzerInterface}) || !slices.Contains(opened.Interfaces.Imports, component.InvocationContextInterface) {
		t.Fatalf("component interfaces = %+v", opened.Interfaces)
	}
	core, err := Open(t.Context(), coreFixture(t, coreMetadata))
	if err != nil || core.Interfaces != nil {
		t.Fatalf("core module interfaces = %+v, %v", core.Interfaces, err)
	}
	invalid := append(unpackagedFixture(t, "component-no-sudo"), 0xff)
	if _, err := Open(t.Context(), appendFixtureMetadata(t, invalid, componentMetadata)); err == nil || errors.Is(err, ErrUnsupportedContract) {
		t.Fatalf("opened a component the host cannot parse: %v", err)
	}
}

const resolverMetadata = `{"metadata_version":1,"transport":"wasm-component","id":"commitish","name":"Commitish","description":"Registry resolver fixture","license":"MIT","repository":"https://github.com/example/plugin","plugin_version":"1.0.0","interface":"` + component.ReferenceResolverInterface + `","wit_sha256":"` + componentContractDigest + `"}`

func TestReferenceResolverComponent(t *testing.T) {
	path := appendFixtureMetadata(t, component.BuiltinCommitishArtifact().Bytes, resolverMetadata)
	result, err := Validate(t.Context(), testAsOf, path)
	if err != nil {
		t.Fatal(err)
	}
	if result.PluginID != "commitish" || len(result.Rules) != 0 || !slices.Contains(result.Checks, "reference-resolver") || result.Contract != component.ReferenceResolverInterface+"#sha256="+componentContractDigest {
		t.Fatalf("wrong resolver evidence: %+v", result)
	}
}

func TestAcceptedLegacyContractDigest(t *testing.T) {
	legacy := strings.Replace(componentMetadata, `"wit_sha256"`, `"contract_sha256"`, 1)
	result, err := Validate(t.Context(), testAsOf, packagedFixture(t, "component-no-sudo", legacy))
	if err != nil {
		t.Fatal(err)
	}
	if result.Contract != component.AnalyzerInterface+"#sha256="+componentContractDigest {
		t.Fatalf("legacy digest lost from the contract: %s", result.Contract)
	}
	both := strings.Replace(componentMetadata, `"wit_sha256"`, `"contract_sha256":"`+componentContractDigest+`","wit_sha256"`, 1)
	if _, err := Validate(t.Context(), testAsOf, packagedFixture(t, "component-no-sudo", both)); err == nil || errors.Is(err, ErrUnsupportedContract) {
		t.Fatalf("accepted two contract digests: %v", err)
	}
}

func TestImportThisHostDoesNotProvideIsUnsupported(t *testing.T) {
	retired := "kjanat:actionlint/prepared-scripts@0.2.0"
	built := wasmcomponent.Build([]string{retired}, []string{component.AnalyzerInterface}, nil)
	if _, err := Validate(t.Context(), testAsOf, appendFixtureMetadata(t, built, componentMetadata)); !errors.Is(err, ErrUnsupportedContract) || !strings.Contains(err.Error(), retired) {
		t.Fatalf("an import this host does not provide must be unsupported, got %v", err)
	}
	misplaced := wasmcomponent.Build([]string{component.RepositoryObjectsInterface}, []string{component.AnalyzerInterface}, nil)
	if _, err := Validate(t.Context(), testAsOf, appendFixtureMetadata(t, misplaced, componentMetadata)); err == nil || errors.Is(err, ErrUnsupportedContract) {
		t.Fatalf("a provided import outside its role must fail, got %v", err)
	}
}
