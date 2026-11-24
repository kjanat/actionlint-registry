package registry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"registry.actionlint.kjanat.dev/internal/compatibility"
)

type boundedBuffer struct {
	buffer bytes.Buffer
	limit  int
}

func (b *boundedBuffer) Bytes() []byte { return b.buffer.Bytes() }

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.buffer.Len() {
		return 0, errors.New("validator output exceeds limit")
	}
	return b.buffer.Write(p)
}

// CheckCompatibility runs a trusted, explicitly selected checker on a checksum-verified
// snapshot. It excludes registry credentials but does not provide an OS sandbox.
func CheckCompatibility(ctx context.Context, executable, path string, entry Entry, runnerAsOf string) (evidence compatibility.Evidence, err error) {
	if err = entry.Submission.Validate(); err != nil {
		return evidence, err
	}
	if entry.Submission.IsOCI() {
		return evidence, errors.New("this checker accepts local package bytes; OCI graph checks are unsupported")
	}
	return CheckArtifact(ctx, executable, path, entry.Submission.Digest(), runnerAsOf)
}

// CheckArtifact observes a local candidate without requiring publication. The
// caller supplies the inspected digest; the checker receives a verified snapshot.
// A protocol 2 checker receives a non-empty runnerAsOf and otherwise uses the
// current UTC date. A protocol 1 checker receives no date and reports none.
func CheckArtifact(ctx context.Context, executable, path, expectedDigest, runnerAsOf string) (evidence compatibility.Evidence, err error) {
	executable, err = filepath.Abs(executable)
	if err != nil {
		return evidence, err
	}
	if !digestPattern.MatchString(expectedDigest) {
		return evidence, errors.New("invalid checker input digest")
	}
	if runnerAsOf != "" && !compatibility.ValidDate(runnerAsOf) {
		return evidence, errors.New("invalid runner assessment date")
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	dir, err := os.MkdirTemp("", "registry-checker-")
	if err != nil {
		return evidence, err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(dir)) }()
	checkerPath := filepath.Join(dir, "checker")
	if runtime.GOOS == "windows" {
		checkerPath += ".exe"
	}
	evidence.CheckerSHA256, err = snapshotFile(executable, checkerPath, 256<<20, 0o700)
	if err != nil {
		return evidence, err
	}
	snapshot := filepath.Join(dir, "plugin"+filepath.Ext(path))
	digest, err := snapshotFile(path, snapshot, MaxArtifactBytes, 0o600)
	if err != nil {
		return evidence, err
	}
	if digest != expectedDigest {
		return evidence, errors.New("checker input checksum differs from inspected artifact")
	}
	protocol, err := checkerProtocol(ctx, checkerPath, dir)
	if err != nil {
		return evidence, err
	}
	var args []string
	if protocol >= 2 && runnerAsOf != "" {
		args = append(args, "--runner-as-of", runnerAsOf)
	}
	stdout := &boundedBuffer{limit: 1 << 20}
	if err = checkerCommand(ctx, checkerPath, dir, stdout, append(args, snapshot)...).Run(); err != nil {
		return evidence, fmt.Errorf("checker process: %w", err)
	}
	if err = jsonv2.Unmarshal(stdout.Bytes(), &evidence.Report, jsonv2.RejectUnknownMembers(true)); err != nil {
		return evidence, fmt.Errorf("checker response: %w", err)
	}
	evidence.ObservedAt = time.Now().UTC()
	if evidence.Report.ArtifactSHA256 != expectedDigest {
		return evidence, errors.New("checker report refers to a different artifact")
	}
	if evidence.Report.SchemaVersion != protocol {
		return evidence, fmt.Errorf("checker answered protocol %d but reported schema_version %d", protocol, evidence.Report.SchemaVersion)
	}
	if protocol >= 2 {
		expected := runnerAsOf
		if expected == "" {
			expected = evidence.ObservedAt.Format(time.DateOnly)
		}
		if evidence.Report.RunnerAsOf != expected {
			return evidence, fmt.Errorf("checker used runner assessment date %q instead of %q", evidence.Report.RunnerAsOf, expected)
		}
	}
	return evidence, evidence.Validate()
}

// checkerProtocol asks the checker for its protocol version. A protocol 1
// checker treats the probe as a missing artifact: it exits non-zero and prints
// nothing to stdout.
func checkerProtocol(ctx context.Context, checkerPath, dir string) (int, error) {
	stdout := &boundedBuffer{limit: 64}
	err := checkerCommand(ctx, checkerPath, dir, stdout, compatibility.ProtocolProbe).Run()
	answer := strings.TrimSpace(string(stdout.Bytes()))
	var exit *exec.ExitError
	switch {
	case err == nil && answer == strconv.Itoa(compatibility.ProtocolVersion):
		return compatibility.ProtocolVersion, nil
	case errors.As(err, &exit) && answer == "":
		return 1, nil
	case err != nil:
		return 0, fmt.Errorf("checker protocol probe: %w", err)
	default:
		return 0, fmt.Errorf("unsupported checker protocol %q", answer)
	}
}

func checkerCommand(ctx context.Context, checkerPath, dir string, stdout io.Writer, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, checkerPath, args...)
	cmd.Dir = dir
	cmd.Env = []string{"GOMEMLIMIT=512MiB", "TMPDIR=" + dir, "TMP=" + dir, "TEMP=" + dir}
	if root, ok := os.LookupEnv("SystemRoot"); ok {
		cmd.Env = append(cmd.Env, "SystemRoot="+root)
	}
	cmd.WaitDelay = time.Second
	cmd.Stdout = stdout
	cmd.Stderr = &boundedBuffer{limit: 64 << 10}
	return cmd
}

// snapshotFile hashes the bytes it copies, so execution cannot race a replacement
// of the operator's checker executable or local artifact.
func snapshotFile(sourcePath, targetPath string, limit int64, mode os.FileMode) (digest string, err error) {
	source, err := os.Open(sourcePath)
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, source.Close()) }()
	stat, err := source.Stat()
	if err != nil {
		return "", err
	}
	if !stat.Mode().IsRegular() || stat.Size() > limit {
		return "", errors.New("snapshot requires a bounded regular file")
	}
	target, err := os.OpenFile(targetPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, target.Close()) }()
	hash := sha256.New()
	size, err := io.Copy(io.MultiWriter(target, hash), io.LimitReader(source, limit+1))
	if err != nil {
		return "", err
	}
	if size > limit {
		return "", errors.New("snapshot exceeds size limit")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
