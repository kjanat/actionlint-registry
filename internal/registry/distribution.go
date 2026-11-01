package registry

import (
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Distribution is a closed, comparable source description. Its zero value is
// reserved for legacy schema_version 1 submissions.
type Distribution struct{ kind, name, digest, reference string }

var ociRepositoryPattern = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*$`)
var ociHostPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$`)

func validOCIPort(port string) bool {
	if port == "" {
		return true
	}
	if len(port) > 5 {
		return false
	}
	for _, digit := range port {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	number, err := strconv.ParseUint(port, 10, 16)
	return err == nil && number > 0
}

func ReleaseAsset(name, digest string) (Distribution, error) {
	if !namePattern.MatchString(name) || !digestPattern.MatchString(digest) {
		return Distribution{}, errors.New("release asset requires a filename and SHA256")
	}
	return Distribution{kind: "release-asset", name: name, digest: digest}, nil
}

func OCIReference(reference string) (Distribution, error) {
	u, err := url.Parse(reference)
	if err != nil || u.Scheme != "oci" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.Contains(reference, "#") || !validOCIPort(u.Port()) || strings.HasSuffix(u.Host, ":") || strings.ToLower(u.Host) != u.Host || u.RawPath != "" {
		return Distribution{}, errors.New("OCI reference requires oci://host/repository@sha256:digest")
	}
	repository, digest, ok := strings.Cut(strings.TrimPrefix(u.Path, "/"), "@sha256:")
	if !ok || len(reference) > 2048 || !ociHostPattern.MatchString(u.Hostname()) || !ociRepositoryPattern.MatchString(repository) || !digestPattern.MatchString(digest) {
		return Distribution{}, errors.New("OCI reference must contain a canonical repository and pinned SHA256 digest")
	}
	return Distribution{kind: "oci", reference: reference, digest: digest}, nil
}

func (d Distribution) IsZero() bool      { return d == Distribution{} }
func (d Distribution) IsOCI() bool       { return d.kind == "oci" }
func (d Distribution) Reference() string { return d.reference }

func (d Distribution) MarshalJSON() ([]byte, error) {
	switch d.kind {
	case "release-asset":
		return json.Marshal(struct {
			Type   string `json:"type"`
			Name   string `json:"name"`
			SHA256 string `json:"sha256"`
		}{d.kind, d.name, d.digest})
	case "oci":
		return json.Marshal(struct {
			Type      string `json:"type"`
			Reference string `json:"reference"`
		}{d.kind, d.reference})
	default:
		return nil, errors.New("invalid artifact distribution")
	}
}

func (d *Distribution) UnmarshalJSON(data []byte) error {
	var wire struct {
		Type      string  `json:"type"`
		Name      *string `json:"name"`
		SHA256    *string `json:"sha256"`
		Reference *string `json:"reference"`
	}
	if err := jsonv2.Unmarshal(data, &wire, jsonv2.RejectUnknownMembers(true)); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := jsonv2.Unmarshal(data, &fields); err != nil {
		return err
	}
	_, hasName := fields["name"]
	_, hasDigest := fields["sha256"]
	_, hasReference := fields["reference"]
	var result Distribution
	var err error
	switch {
	case wire.Type == "release-asset" && wire.Name != nil && wire.SHA256 != nil && !hasReference:
		result, err = ReleaseAsset(*wire.Name, *wire.SHA256)
	case wire.Type == "oci" && wire.Reference != nil && !hasName && !hasDigest:
		result, err = OCIReference(*wire.Reference)
	default:
		return errors.New("invalid artifact distribution fields")
	}
	if err == nil {
		*d = result
	}
	return err
}

func (s Submission) IsOCI() bool { return s.SchemaVersion == 2 && s.Artifact.IsOCI() }
func (s Submission) Digest() string {
	if s.SchemaVersion == 2 {
		return s.Artifact.digest
	}
	return s.SHA256
}
func (s Submission) AssetName() string {
	if s.SchemaVersion == 2 {
		return s.Artifact.name
	}
	return s.Asset
}

// UnmarshalJSON preserves v1 wire fields while refusing mixed source protocols.
func (s *Submission) UnmarshalJSON(data []byte) error {
	type wire Submission
	var value wire
	if err := jsonv2.Unmarshal(data, &value, jsonv2.RejectUnknownMembers(true)); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := jsonv2.Unmarshal(data, &fields); err != nil {
		return err
	}
	_, asset := fields["asset"]
	_, digest := fields["sha256"]
	_, distribution := fields["artifact"]
	if value.SchemaVersion == 1 && (!asset || !digest || distribution) || value.SchemaVersion == 2 && (asset || digest || !distribution) {
		return errors.New("submission source fields disagree with schema_version")
	}
	*s = Submission(value)
	return nil
}

func (s Submission) validateRepository() error {
	if s.Provider != "github" && s.Provider != "gitlab" {
		return errors.New("provider must be github or gitlab")
	}
	if len(s.Repository) > 512 || s.Provider == "github" && !repositoryPattern.MatchString(s.Repository) || s.Provider == "gitlab" && !gitlabRepositoryPattern.MatchString(s.Repository) {
		return errors.New("repository must be owner/repository")
	}
	return nil
}

func validAsset(name, kind string) bool {
	if !namePattern.MatchString(name) {
		return false
	}
	if kind == "manifest" {
		return strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".json.gz")
	}
	return strings.HasSuffix(name, ".wasm") || strings.HasSuffix(name, ".wasm.gz")
}
