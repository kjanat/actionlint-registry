package artifact

import (
	"errors"
	"testing"

	"github.com/go-quickjs/go-quickjs/jsregexp"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

type exhaustedPattern struct{ ecmaRegexp }

func (exhaustedPattern) MatchString(string) (bool, error) { return false, jsregexp.ErrComplexity }

func TestSettingsCompilerReportsMatchBudgetExhaustion(t *testing.T) {
	for _, tt := range []struct {
		keyword  string
		schema   map[string]any
		instance any
	}{
		{"pattern", map[string]any{"pattern": "^a"}, "alpha"},
		{"patternProperties", map[string]any{"patternProperties": map[string]any{"^a": false}}, map[string]any{"alpha": true}},
	} {
		t.Run(tt.keyword, func(t *testing.T) {
			err := withSettingsCompiler(func(c *jsonschema.Compiler) error {
				if err := c.AddResource(settingBase, tt.schema); err != nil {
					return err
				}
				s, err := c.Compile(settingBase)
				if err != nil {
					return err
				}
				exhaust := func(r jsonschema.Regexp) {
					p := r.(*schemaPattern)
					p.ecmaRegexp = exhaustedPattern{p.ecmaRegexp}
				}
				if s.Pattern != nil {
					exhaust(s.Pattern)
				}
				for pattern := range s.PatternProperties {
					exhaust(pattern)
				}
				err = s.Validate(tt.instance)
				// A false match rejects a string but skips a patternProperties rule.
				if (err == nil) != (tt.keyword == "patternProperties") {
					t.Fatalf("unexpected validator result for %s: %v", tt.keyword, err)
				}
				return err
			})
			if !errors.Is(err, jsregexp.ErrComplexity) {
				t.Fatalf("got %v, want %v", err, jsregexp.ErrComplexity)
			}
		})
	}
}

func TestSettingsCompilerPreservesMatchAndNonmatch(t *testing.T) {
	err := withSettingsCompiler(func(c *jsonschema.Compiler) error {
		if err := c.AddResource(settingBase, map[string]any{"pattern": "^a"}); err != nil {
			return err
		}
		s, err := c.Compile(settingBase)
		if err != nil {
			return err
		}
		if err := s.Validate("alpha"); err != nil {
			return err
		}
		if s.Validate("beta") == nil {
			return errors.New("beta matched ^a")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
