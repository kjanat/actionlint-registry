package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"actionlint.kjanat.dev/v2/internal/model/lifecycle"
	"actionlint.kjanat.dev/v2/registry/validation/internal/validation"
)

const protocolVersion = 2

type host struct {
	Name     string `json:"name"`
	Revision string `json:"revision"`
}
type report struct {
	SchemaVersion  int      `json:"schema_version"`
	ArtifactSHA256 string   `json:"artifact_sha256"`
	Host           host     `json:"host"`
	Policy         string   `json:"policy"`
	Outcome        string   `json:"outcome"`
	Checks         []string `json:"checks"`
	RunnerAsOf     string   `json:"runner_as_of"`
	Detail         string   `json:"detail,omitempty"`
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("actionlint-checker", flag.ContinueOnError)
	asOfFlag := flags.String("runner-as-of", "", "Runner assessment date (YYYY-MM-DD); defaults to the current UTC date")
	protocolFlag := flags.Bool("protocol", false, "Print the report protocol version and exit")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *protocolFlag && *asOfFlag == "" && flags.NArg() == 0 {
		_, err := fmt.Println(protocolVersion)
		return err
	}
	if *protocolFlag || flags.NArg() != 1 {
		return errors.New("usage: actionlint-checker --protocol | [--runner-as-of YYYY-MM-DD] <local-artifact>")
	}
	asOf := lifecycle.DateOf(time.Now())
	if *asOfFlag != "" {
		parsed, err := lifecycle.ParseDate(*asOfFlag)
		if err != nil {
			return fmt.Errorf("--runner-as-of: %w", err)
		}
		asOf = parsed
	}
	if validation.HostCommit == "" {
		return errors.New("checker build lacks the actionlint host module revision")
	}
	path := flags.Arg(0)
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	hash := sha256.New()
	size, hashErr := io.Copy(hash, io.LimitReader(file, (64<<20)+1))
	if err = errors.Join(hashErr, file.Close()); err != nil {
		return err
	}
	if size > 64<<20 {
		return errors.New("artifact exceeds 64 MiB")
	}
	reply := report{SchemaVersion: protocolVersion, ArtifactSHA256: hex.EncodeToString(hash.Sum(nil)), Host: host{Name: "actionlint", Revision: validation.HostCommit}, Policy: "actionlint-smoke/1", Outcome: "passed", Checks: []string{}, RunnerAsOf: asOf.String()}
	result, err := validation.Validate(ctx, asOf, path)
	if err != nil {
		reply.Outcome = "failed"
		if errors.Is(err, validation.ErrUnsupportedContract) {
			reply.Outcome = "unsupported"
		}
		reply.Detail = err.Error()
	} else {
		reply.Checks = result.Checks
	}
	return json.NewEncoder(os.Stdout).Encode(reply)
}
