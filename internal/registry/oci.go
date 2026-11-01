package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"registry.actionlint.kjanat.dev/internal/artifact"
)

const (
	ociManifest = "application/vnd.oci.image.manifest.v1+json"
	ociIndex    = "application/vnd.oci.image.index.v1+json"
	ociWASM     = "application/wasm"
	ociProcess  = "application/vnd.actionlint.tool-provider.v1+json"
)

type ociDescriptor struct {
	MediaType string   `json:"mediaType"`
	Digest    string   `json:"digest"`
	Size      int64    `json:"size"`
	URLs      []string `json:"urls"`
	Data      []byte   `json:"data,omitempty"`
}

type ociDocument struct {
	SchemaVersion int             `json:"schemaVersion"`
	MediaType     string          `json:"mediaType"`
	Config        *ociDescriptor  `json:"config"`
	Layers        []ociDescriptor `json:"layers"`
	Manifests     []ociDescriptor `json:"manifests"`
	Subject       *ociDescriptor  `json:"subject"`
}

// OCIInspector reads public digest-addressed graphs without executing their
// contents. The production transport revalidates DNS at every connection.
type OCIInspector struct{ client *http.Client }

func publicAddress(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
		return false
	}
	if address.Is6() && !netip.MustParsePrefix("2000::/3").Contains(address) {
		return false
	}
	for _, block := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32", "2002::/16", "2001::/32"} {
		if netip.MustParsePrefix(block).Contains(address) {
			return false
		}
	}
	return true
}

func publicDial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port == "" || !validOCIPort(port) {
		return nil, errors.New("OCI requires public HTTPS endpoints")
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, errors.New("OCI endpoint has no public addresses")
	}
	for _, ip := range addresses {
		if !publicAddress(ip) {
			return nil, errors.New("OCI endpoint resolves to a non-public address")
		}
	}
	dialer := net.Dialer{Timeout: 10 * time.Second}
	var failures []error
	for _, ip := range addresses {
		connection, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return connection, nil
		}
		failures = append(failures, err)
	}
	return nil, errors.Join(failures...)
}

func NewOCIInspector() *OCIInspector {
	transport := &http.Transport{DialContext: publicDial, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second, MaxResponseHeaderBytes: 64 << 10, MaxIdleConns: 4, IdleConnTimeout: 15 * time.Second}
	return &OCIInspector{client: &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 5 || req.URL.Scheme != "https" || req.URL.User != nil || !validOCIPort(req.URL.Port()) || strings.HasSuffix(req.URL.Host, ":") {
			return errors.New("invalid OCI redirect")
		}
		if len(via) > 0 && req.URL.Host != via[len(via)-1].URL.Host {
			req.Header.Del("Authorization")
		}
		return nil
	}}}
}

var bearerParameter = regexp.MustCompile(`(?:^|,)\s*([a-z]+)="([^"\\]*)"\s*`)

func (o *OCIInspector) request(ctx context.Context, target, token string) (*http.Response, error) {
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || !validOCIPort(u.Port()) || strings.HasSuffix(u.Host, ":") {
		return nil, errors.New("invalid public OCI endpoint")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", ociManifest+", "+ociIndex)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return o.client.Do(req)
}

func (o *OCIInspector) fetch(ctx context.Context, target, repository string, limit int64) (data []byte, err error) {
	resp, err := o.request(ctx, target, "")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		challenge := resp.Header.Get("WWW-Authenticate")
		if closeErr := resp.Body.Close(); closeErr != nil {
			return nil, closeErr
		}
		scheme, parametersText, found := strings.Cut(challenge, " ")
		if !found || !strings.EqualFold(scheme, "Bearer") {
			return nil, errors.New("OCI registry requires unsupported authentication")
		}
		parameters := map[string]string{}
		remaining := strings.TrimSpace(parametersText)
		for remaining != "" {
			match := bearerParameter.FindStringSubmatchIndex(remaining)
			if match == nil || match[0] != 0 {
				return nil, errors.New("invalid OCI bearer challenge")
			}
			key, value := remaining[match[2]:match[3]], remaining[match[4]:match[5]]
			if _, duplicate := parameters[key]; duplicate {
				return nil, errors.New("duplicate OCI bearer parameter")
			}
			parameters[key] = value
			remaining = remaining[match[1]:]
		}
		realm, parseErr := url.Parse(parameters["realm"])
		if parseErr != nil || realm.Scheme != "https" || realm.Host == "" || realm.User != nil || realm.Fragment != "" {
			return nil, errors.New("invalid anonymous OCI auth realm")
		}
		query := realm.Query()
		query.Set("service", parameters["service"])
		query.Set("scope", "repository:"+repository+":pull")
		realm.RawQuery = query.Encode()
		auth, authErr := o.request(ctx, realm.String(), "")
		if authErr != nil {
			return nil, authErr
		}
		authData, readErr := io.ReadAll(io.LimitReader(auth.Body, (64<<10)+1))
		if err := errors.Join(readErr, auth.Body.Close()); err != nil {
			return nil, err
		}
		if auth.StatusCode != http.StatusOK || len(authData) > 64<<10 {
			return nil, errors.New("anonymous OCI authorization failed")
		}
		var response struct {
			Token       string `json:"token"`
			AccessToken string `json:"access_token"`
		}
		if err := jsonv2.Unmarshal(authData, &response); err != nil {
			return nil, err
		}
		token := response.Token
		if token == "" {
			token = response.AccessToken
		}
		if token == "" || len(token) > 32<<10 || strings.ContainsAny(token, "\r\n") {
			return nil, errors.New("invalid anonymous OCI bearer token")
		}
		resp, err = o.request(ctx, target, token)
		if err != nil {
			return nil, err
		}
	}
	defer func() { err = errors.Join(err, resp.Body.Close()) }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OCI registry HTTP %d", resp.StatusCode)
	}
	data, err = io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err == nil && int64(len(data)) > limit {
		err = reject("OCI object exceeds size limit")
	}
	return data, err
}

func validateDescriptor(d ociDescriptor) error {
	if !strings.HasPrefix(d.Digest, "sha256:") || !digestPattern.MatchString(strings.TrimPrefix(d.Digest, "sha256:")) || d.Size < 0 || d.Size > MaxArtifactBytes || d.MediaType == "" || len(d.URLs) != 0 {
		return reject("invalid OCI descriptor or external object URL")
	}
	return nil
}

func verifyOCI(data []byte, digest string, size int64) error {
	sum := sha256.Sum256(data)
	if "sha256:"+hex.EncodeToString(sum[:]) != digest || size >= 0 && int64(len(data)) != size {
		return reject("OCI object digest or size mismatch")
	}
	return nil
}

func sameDeclaration(a, b artifact.Declaration) bool {
	return a.Kind == b.Kind && a.PluginID == b.PluginID && a.PluginVersion == b.PluginVersion && a.Repository == b.Repository && a.Contract == b.Contract
}

// Inspect binds the discovery declaration to the root index/manifest digest,
// while independently checking every referenced descriptor and primary layer.
func (o *OCIInspector) Inspect(ctx context.Context, reference string) (result artifact.Declaration, err error) {
	distribution, err := OCIReference(reference)
	if err != nil {
		return result, err
	}
	u, _ := url.Parse(reference)
	repository, _, _ := strings.Cut(strings.TrimPrefix(u.Path, "/"), "@")
	base := "https://" + u.Host + "/v2/" + repository
	return inspectOCI(ctx, distribution, ociObjects{
		manifest: func(ctx context.Context, digest string, limit int64) ([]byte, error) {
			return o.fetch(ctx, base+"/manifests/"+digest, repository, limit)
		},
		blob: func(ctx context.Context, digest string, limit int64) ([]byte, error) {
			return o.fetch(ctx, base+"/blobs/"+digest, repository, limit)
		},
	})
}

type ociRead func(context.Context, string, int64) ([]byte, error)

type ociObjects struct {
	manifest, blob ociRead
	verified       func(string, []byte) error
}

// Content embedded in a descriptor has the same size/digest requirements as a
// downloaded blob. A local candidate snapshots both forms after verification.
func (s ociObjects) content(ctx context.Context, descriptor ociDescriptor, limit int64, read ociRead) ([]byte, error) {
	var data []byte
	var err error
	if descriptor.Size > limit {
		return nil, reject("OCI object exceeds size limit")
	}
	if descriptor.Data != nil {
		if int64(len(descriptor.Data)) > limit {
			return nil, reject("embedded OCI object exceeds size limit")
		}
		data = descriptor.Data
	} else {
		data, err = read(ctx, descriptor.Digest, limit)
	}
	if err != nil {
		return nil, err
	}
	if err := verifyOCI(data, descriptor.Digest, descriptor.Size); err != nil {
		return nil, err
	}
	if s.verified != nil {
		if err := s.verified(descriptor.Digest, data); err != nil {
			return nil, err
		}
	}
	return data, ctx.Err()
}

// Public registries and local layouts share graph admission rules. Readers
// acquire bytes; only this traversal interprets their descriptors.
func inspectOCI(ctx context.Context, distribution Distribution, source ociObjects) (result artifact.Declaration, err error) {
	ctx, cancel := context.WithTimeout(ctx, 75*time.Second)
	defer cancel()
	directory, err := os.MkdirTemp("", "registry-oci-")
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(directory)) }()
	var total int64
	objects := 0
	active := map[string]bool{}
	var root []byte
	rootDigest := "sha256:" + distribution.digest
	var visit func(ociDescriptor, int) error
	visit = func(descriptor ociDescriptor, depth int) error {
		var err error
		objects++
		if depth > 4 || objects > 128 || active[descriptor.Digest] {
			return reject("OCI graph exceeds bounds or contains a cycle")
		}
		if err := validateDescriptor(descriptor); err != nil {
			return err
		}
		active[descriptor.Digest] = true
		defer delete(active, descriptor.Digest)
		data := root
		if descriptor.Digest != rootDigest {
			data, err = source.content(ctx, descriptor, 4<<20, source.manifest)
			if err != nil {
				return err
			}
		}
		if err = verifyOCI(data, descriptor.Digest, descriptor.Size); err != nil {
			return err
		}
		total += int64(len(data))
		if total > 2*MaxArtifactBytes {
			return reject("OCI graph exceeds 128 MiB")
		}
		var document ociDocument
		if err = jsonv2.Unmarshal(data, &document); err != nil {
			return reject("invalid OCI document JSON")
		}
		if document.SchemaVersion != 2 || document.MediaType != descriptor.MediaType || document.Subject != nil {
			return reject("unsupported OCI document framing")
		}
		switch document.MediaType {
		case ociIndex:
			if len(document.Manifests) == 0 || len(document.Layers) != 0 || document.Config != nil {
				return reject("invalid OCI index")
			}
			for _, child := range document.Manifests {
				if err = visit(child, depth+1); err != nil {
					return err
				}
			}
			return nil
		case ociManifest:
			if document.Config == nil || len(document.Manifests) != 0 || len(document.Layers) == 0 || len(document.Layers) > 64 {
				return reject("invalid OCI manifest")
			}
		default:
			return reject("unsupported OCI manifest media type")
		}
		descriptors := append([]ociDescriptor{*document.Config}, document.Layers...)
		var primary []byte
		primaryType := ""
		blobs := map[string]ociDescriptor{}
		for position, blob := range descriptors {
			if err = validateDescriptor(blob); err != nil {
				return err
			}
			total += blob.Size
			if total > 2*MaxArtifactBytes {
				return reject("OCI graph exceeds 128 MiB")
			}
			content, err := source.content(ctx, blob, blob.Size, source.blob)
			if err != nil {
				return err
			}
			if err = verifyOCI(content, blob.Digest, blob.Size); err != nil {
				return err
			}
			if position == 0 {
				continue
			}
			blobs[blob.Digest] = blob
			if blob.MediaType == ociWASM || blob.MediaType == ociProcess {
				if primary != nil {
					return reject("OCI manifest requires exactly one primary plugin layer")
				}
				primary, primaryType = content, blob.MediaType
			}
		}
		if primary == nil {
			return reject("OCI manifest has no supported primary plugin layer")
		}
		if primaryType == ociProcess {
			if err = validateProcessBlobs(primary, blobs); err != nil {
				return err
			}
		}
		path := filepath.Join(directory, "primary")
		if err = os.WriteFile(path, primary, 0o600); err != nil {
			return err
		}
		declared, err := artifact.Inspect(ctx, path)
		if err != nil {
			return err
		}
		if primaryType == ociProcess && declared.Kind != "manifest" || primaryType == ociWASM && declared.Kind == "manifest" {
			return reject("OCI layer media type disagrees with package kind")
		}
		if result.PluginID != "" && !sameDeclaration(result, declared) {
			return reject("OCI platform variants disagree on discovery identity or contract")
		}
		result = declared
		return nil
	}
	root, err = source.content(ctx, ociDescriptor{Digest: rootDigest, Size: -1}, 4<<20, source.manifest)
	if err != nil {
		return result, err
	}
	if err = verifyOCI(root, "sha256:"+distribution.digest, -1); err != nil {
		return result, err
	}
	var document ociDocument
	if err = jsonv2.Unmarshal(root, &document); err != nil {
		return result, reject("invalid OCI root document")
	}
	if err = visit(ociDescriptor{MediaType: document.MediaType, Digest: "sha256:" + distribution.digest, Size: int64(len(root))}, 0); err != nil {
		return result, err
	}
	result.SHA256 = distribution.digest
	return result, result.Validate()
}

func validateProcessBlobs(data []byte, blobs map[string]ociDescriptor) error {
	var provider struct {
		Artifacts []struct {
			Digest    string `json:"digest"`
			Size      int64  `json:"size"`
			Filename  string `json:"filename"`
			Platform  string `json:"platform"`
			MediaType string `json:"media_type"`
		} `json:"artifacts"`
		Process struct {
			Entry  string `json:"entry"`
			Config struct {
				Transform *struct {
					Digest string `json:"digest"`
				} `json:"transform"`
			} `json:"config"`
			Output struct {
				Transform *struct {
					Digest string `json:"digest"`
				} `json:"transform"`
			} `json:"output"`
		} `json:"process"`
	}
	if err := jsonv2.Unmarshal(data, &provider); err != nil {
		return reject("invalid process provider JSON")
	}
	platforms := map[string]bool{}
	for _, executable := range provider.Artifacts {
		blob, found := blobs[executable.Digest]
		if !found || executable.Size != blob.Size || executable.Filename == "" || executable.Filename != provider.Process.Entry || !namePattern.MatchString(executable.Filename) || executable.Platform == "" || platforms[executable.Platform] || executable.MediaType != "" && executable.MediaType != blob.MediaType {
			return reject("OCI process executable reference does not match a layer")
		}
		platforms[executable.Platform] = true
	}
	for _, transform := range []string{transformDigest(provider.Process.Config.Transform), transformDigest(provider.Process.Output.Transform)} {
		if transform != "" {
			if _, found := blobs[transform]; !found {
				return reject("OCI process transform reference does not match a layer")
			}
		}
	}
	return nil
}

func transformDigest(transform *struct {
	Digest string `json:"digest"`
}) string {
	if transform == nil {
		return ""
	}
	return transform.Digest
}
