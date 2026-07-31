// SPDX-License-Identifier: AGPL-3.0-only

// Command workerd-config-gen generates the Go bindings for workerd's Cap'n
// Proto configuration schema.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	schemaFilename    = "workerd.capnp"
	generatedFilename = schemaFilename + ".go"

	capnpGoModule   = "capnproto.org/go/capnp/v3"
	capnpcGoPackage = capnpGoModule + "/capnpc-go"

	workerdSchemaCommit = "26b5461b7dcc640bb16072f1ba6f2c6df82572ba"
	workerdSchemaURL    = "https://raw.githubusercontent.com/cloudflare/workerd/" +
		workerdSchemaCommit + "/src/workerd/server/workerd.capnp"
	workerdSchemaSHA256 = "8b962175a03921642da743c30b21fb8015ee6bfd7c293c7c9dde2fed46b8beb9"
	maxSchemaBytes      = 1 << 20

	cxxAnnotations = `# Any capnp files imported here must be:
# 1. embedded using wd_cc_embed
# 2. added to ` + "`tryImportBulitin`" + ` in workerd.c++ (grep for '"/workerd/workerd.capnp"').
using Cxx = import "/capnp/c++.capnp";
$Cxx.namespace("workerd::server::config");
$Cxx.allowCancellation;`

	goAnnotations = `using Go = import "/go.capnp";
$Go.package("workerdconfig");
$Go.import("github.com/apoxy-dev/apoxy/pkg/workerd/config");`
)

type options struct {
	capnpPath  string
	outputPath string
}

type compileRequest struct {
	capnpPath  string
	outputDir  string
	pluginPath string
	sourceDir  string
}

type schemaLoader func(context.Context) ([]byte, error)
type compileFunc func(context.Context, compileRequest) error

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "workerd-config-gen: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stderr io.Writer) error {
	flags := flag.NewFlagSet("workerd-config-gen", flag.ContinueOnError)
	flags.SetOutput(stderr)

	var opts options
	flags.StringVar(&opts.capnpPath, "capnp", "capnp", "path to the Cap'n Proto compiler")
	flags.StringVar(&opts.outputPath, "out", "", "path for the generated Go source")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if opts.outputPath == "" {
		return errors.New("-out is required")
	}

	return generate(ctx, opts, loadWorkerdSchema, compileSchema)
}

func generate(ctx context.Context, opts options, load schemaLoader, compile compileFunc) error {
	schema, err := load(ctx)
	if err != nil {
		return err
	}

	tempDir, err := os.MkdirTemp("", "workerd-config-gen-*")
	if err != nil {
		return fmt.Errorf("create temporary directory: %w", err)
	}
	tempDir, err = filepath.Abs(tempDir)
	if err != nil {
		return fmt.Errorf("resolve temporary directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	sourceDir := filepath.Join(tempDir, "source")
	outputDir := filepath.Join(tempDir, "output")
	for _, dir := range []string{sourceDir, outputDir} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			return fmt.Errorf("create temporary directory %q: %w", dir, err)
		}
	}
	if err := os.WriteFile(filepath.Join(sourceDir, schemaFilename), schema, 0o644); err != nil {
		return fmt.Errorf("write workerd schema: %w", err)
	}

	pluginName := "capnpc-go"
	if runtime.GOOS == "windows" {
		pluginName += ".exe"
	}
	if err := compile(ctx, compileRequest{
		capnpPath:  opts.capnpPath,
		outputDir:  outputDir,
		pluginPath: filepath.Join(tempDir, pluginName),
		sourceDir:  sourceDir,
	}); err != nil {
		return err
	}

	generated, err := os.ReadFile(filepath.Join(outputDir, generatedFilename))
	if err != nil {
		return fmt.Errorf("read generated bindings: %w", err)
	}
	current, err := os.ReadFile(opts.outputPath)
	if err == nil && bytes.Equal(current, generated) {
		return nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read current bindings: %w", err)
	}
	return writeAtomically(opts.outputPath, generated)
}

func loadWorkerdSchema(ctx context.Context) ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	schema, err := fetchPinnedFile(ctx, client, workerdSchemaURL, workerdSchemaSHA256)
	if err != nil {
		return nil, fmt.Errorf("fetch workerd schema at %s: %w", workerdSchemaCommit, err)
	}
	return useGoAnnotations(schema)
}

type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

func fetchPinnedFile(ctx context.Context, client httpDoer, url, wantSHA256 string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	request.Header.Set("User-Agent", "apoxy-workerd-config-gen")

	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download returned %s", response.Status)
	}

	contents, err := io.ReadAll(io.LimitReader(response.Body, maxSchemaBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read download: %w", err)
	}
	if len(contents) > maxSchemaBytes {
		return nil, fmt.Errorf("download exceeds %d bytes", maxSchemaBytes)
	}
	gotSHA256 := fmt.Sprintf("%x", sha256.Sum256(contents))
	if gotSHA256 != wantSHA256 {
		return nil, fmt.Errorf("SHA-256 is %s, want %s", gotSHA256, wantSHA256)
	}
	return contents, nil
}

func useGoAnnotations(schema []byte) ([]byte, error) {
	if bytes.Count(schema, []byte(cxxAnnotations)) != 1 {
		return nil, errors.New("upstream workerd schema does not contain the expected C++ annotations")
	}
	return bytes.Replace(schema, []byte(cxxAnnotations), []byte(goAnnotations), 1), nil
}

func compileSchema(ctx context.Context, request compileRequest) error {
	request, err := resolveCompileRequest(request)
	if err != nil {
		return err
	}
	if err := runCommand(
		ctx,
		"",
		"build capnpc-go",
		"go", "build", "-o", request.pluginPath, capnpcGoPackage,
	); err != nil {
		return err
	}

	moduleDir, err := goModuleDir(ctx, capnpGoModule)
	if err != nil {
		return err
	}
	return runCommand(
		ctx,
		request.sourceDir,
		"compile workerd schema",
		request.capnpPath,
		"compile",
		"-I", filepath.Join(moduleDir, "std"),
		"-o"+request.pluginPath+":"+request.outputDir,
		schemaFilename,
	)
}

func resolveCompileRequest(request compileRequest) (compileRequest, error) {
	compiler, err := exec.LookPath(request.capnpPath)
	if err != nil {
		return compileRequest{}, fmt.Errorf("resolve Cap'n Proto compiler %q: %w", request.capnpPath, err)
	}
	request.capnpPath, err = filepath.Abs(compiler)
	if err != nil {
		return compileRequest{}, fmt.Errorf("resolve Cap'n Proto compiler path: %w", err)
	}

	paths := []struct {
		name  string
		value *string
	}{
		{name: "output directory", value: &request.outputDir},
		{name: "plugin path", value: &request.pluginPath},
		{name: "source directory", value: &request.sourceDir},
	}
	for _, path := range paths {
		*path.value, err = filepath.Abs(*path.value)
		if err != nil {
			return compileRequest{}, fmt.Errorf("resolve %s: %w", path.name, err)
		}
	}
	return request, nil
}

func goModuleDir(ctx context.Context, module string) (string, error) {
	cmd := exec.CommandContext(ctx, "go", "list", "-m", "-f", "{{.Dir}}", module)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", commandError("locate "+module, err, output)
	}
	dir := strings.TrimSpace(string(output))
	if dir == "" {
		return "", fmt.Errorf("locate %s: go list returned an empty directory", module)
	}
	return dir, nil
}

func runCommand(ctx context.Context, dir, action, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return commandError(action, err, output)
	}
	return nil
}

func commandError(action string, err error, output []byte) error {
	detail := strings.TrimSpace(string(output))
	if detail != "" {
		return fmt.Errorf("%s: %w: %s", action, err, detail)
	}
	return fmt.Errorf("%s: %w", action, err)
}

func writeAtomically(path string, contents []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	file, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return fmt.Errorf("create temporary output: %w", err)
	}
	tempPath := file.Name()
	defer os.Remove(tempPath)

	if err := file.Chmod(0o644); err != nil {
		file.Close()
		return fmt.Errorf("set generated file permissions: %w", err)
	}
	if _, err := file.Write(contents); err != nil {
		file.Close()
		return fmt.Errorf("write generated file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close generated file: %w", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("replace generated file: %w", err)
	}
	return nil
}
