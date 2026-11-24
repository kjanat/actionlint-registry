// Package compatibility defines host-specific observations independently of plugin ABIs.
package compatibility

import (
	"errors"
	"regexp"
	"strings"
	"time"
)

// ProtocolVersion 2 adds the --protocol probe, the --runner-as-of flag and the
// required runner_as_of report field. Version 3 adds the imports and exports
// report fields. Version 1 checkers accept neither flag.
const ProtocolVersion = 3

// ProtocolProbe is the argument a version 2 or later checker answers with its
// protocol version instead of checking an artifact.
const ProtocolProbe = "--protocol"

var digest = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Host struct {
	Name     string `json:"name"`
	Revision string `json:"revision"`
}

// Report is the versioned wire response from an explicitly selected checker.
// Unsupported means the checker cannot assess this contract; it is not a failure.
type Report struct {
	SchemaVersion  int      `json:"schema_version"`
	ArtifactSHA256 string   `json:"artifact_sha256"`
	Host           Host     `json:"host"`
	Policy         string   `json:"policy"`
	Outcome        string   `json:"outcome"`
	Checks         []string `json:"checks"`
	RunnerAsOf     string   `json:"runner_as_of,omitempty"`
	Detail         string   `json:"detail,omitempty"`
	Imports        []string `json:"imports,omitzero"`
	Exports        []string `json:"exports,omitzero"`
}

func (r Report) Validate() error {
	if r.SchemaVersion < 1 || r.SchemaVersion > ProtocolVersion || !digest.MatchString(r.ArtifactSHA256) || !bounded(r.Host.Name, 128) || !bounded(r.Host.Revision, 256) || !bounded(r.Policy, 256) || len(r.Detail) > 16384 || len(r.Checks) > 4096 {
		return errors.New("invalid compatibility report identity or bounds")
	}
	switch {
	case r.SchemaVersion == 1 && r.RunnerAsOf != "":
		return errors.New("protocol 1 reports carry no runner assessment date")
	case r.SchemaVersion >= 2 && !ValidDate(r.RunnerAsOf):
		return errors.New("invalid runner assessment date")
	}
	switch r.Outcome {
	case "passed":
		if len(r.Checks) == 0 || r.Detail != "" {
			return errors.New("passed report requires checks and no error")
		}
	case "failed", "unsupported":
		if !bounded(r.Detail, 16384) {
			return errors.New("unsuccessful report requires a reason")
		}
	default:
		return errors.New("unknown compatibility outcome")
	}
	for _, check := range r.Checks {
		if !bounded(check, 256) {
			return errors.New("invalid compatibility check name")
		}
	}
	if r.HasInterfaces() != (r.Exports != nil) {
		return errors.New("compatibility report requires both imports and exports or neither")
	}
	if r.HasInterfaces() && r.SchemaVersion < 3 {
		return errors.New("protocol 1 and 2 reports carry no interfaces")
	}
	for _, names := range [][]string{r.Imports, r.Exports} {
		if len(names) > 4096 {
			return errors.New("compatibility report lists more than 4096 interfaces")
		}
		for _, name := range names {
			if !bounded(name, 512) {
				return errors.New("invalid interface name")
			}
		}
	}
	return nil
}

func (r Report) HasInterfaces() bool { return r.Imports != nil }

func ValidDate(value string) bool {
	date, err := time.Parse(time.DateOnly, value)
	return err == nil && date.Format(time.DateOnly) == value
}

func bounded(value string, limit int) bool {
	return len(value) > 0 && len(value) <= limit && !strings.ContainsAny(value, "\x00\r\n")
}

// Evidence binds an observation to the exact checker executable used by the operator.
// Host identities are checker claims, not publisher-controlled release metadata.
type Evidence struct {
	Report        Report    `json:"report"`
	CheckerSHA256 string    `json:"checker_sha256"`
	ObservedAt    time.Time `json:"observed_at"`
}

func (e Evidence) Validate() error {
	if err := e.Report.Validate(); err != nil {
		return err
	}
	if !digest.MatchString(e.CheckerSHA256) || e.ObservedAt.IsZero() || e.ObservedAt.After(time.Now().Add(time.Minute)) {
		return errors.New("invalid compatibility observation")
	}
	return nil
}
