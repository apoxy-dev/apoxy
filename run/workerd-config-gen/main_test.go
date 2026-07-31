// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestGenerate(t *testing.T) {
	t.Parallel()

	const schema = "schema"
	const generated = "// generated\n"
	const stale = "// stale\n"

	cases := []struct {
		name        string
		current     string
		hasCurrent  bool
		loadErr     error
		compileErr  error
		writeOutput bool
		want        string
		wantErr     string
	}{
		{
			name:        "create",
			writeOutput: true,
			want:        generated,
		},
		{
			name:        "replace stale",
			current:     stale,
			hasCurrent:  true,
			writeOutput: true,
			want:        generated,
		},
		{
			name:        "leave current",
			current:     generated,
			hasCurrent:  true,
			writeOutput: true,
			want:        generated,
		},
		{
			name:       "schema load failure",
			current:    stale,
			hasCurrent: true,
			loadErr:    errors.New("load failed"),
			want:       stale,
			wantErr:    "load failed",
		},
		{
			name:       "compiler failure",
			current:    stale,
			hasCurrent: true,
			compileErr: errors.New("compiler failed"),
			want:       stale,
			wantErr:    "compiler failed",
		},
		{
			name:    "missing compiler output",
			wantErr: "read generated bindings",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			outputPath := filepath.Join(t.TempDir(), generatedFilename)
			if tc.hasCurrent {
				if err := os.WriteFile(outputPath, []byte(tc.current), 0o644); err != nil {
					t.Fatal(err)
				}
			}

			load := func(context.Context) ([]byte, error) {
				return []byte(schema), tc.loadErr
			}
			compile := func(_ context.Context, request compileRequest) error {
				if tc.compileErr != nil {
					return tc.compileErr
				}

				gotSchema, err := os.ReadFile(filepath.Join(request.sourceDir, schemaFilename))
				if err != nil {
					t.Fatal(err)
				}
				if string(gotSchema) != schema {
					t.Errorf("compiler received schema %q, want %q", gotSchema, schema)
				}

				if tc.writeOutput {
					if err := os.WriteFile(
						filepath.Join(request.outputDir, generatedFilename),
						[]byte(generated),
						0o644,
					); err != nil {
						t.Fatal(err)
					}
				}
				return nil
			}

			err := generate(
				context.Background(),
				options{capnpPath: "capnp", outputPath: outputPath},
				load,
				compile,
			)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("generate() error = %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("generate() error = %v, want an error containing %q", err, tc.wantErr)
			}

			got, readErr := os.ReadFile(outputPath)
			if !tc.hasCurrent && tc.want == "" {
				if !errors.Is(readErr, os.ErrNotExist) {
					t.Fatalf("ReadFile() error = %v, want file not to exist", readErr)
				}
				return
			}
			if readErr != nil {
				t.Fatal(readErr)
			}
			if string(got) != tc.want {
				t.Errorf("generated file = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFetchPinnedFile(t *testing.T) {
	t.Parallel()

	contents := []byte("schema")
	checksum := fmt.Sprintf("%x", sha256.Sum256(contents))

	cases := []struct {
		name       string
		statusCode int
		checksum   string
		wantErr    string
	}{
		{name: "valid", statusCode: http.StatusOK, checksum: checksum},
		{name: "bad status", statusCode: http.StatusNotFound, checksum: checksum, wantErr: "404"},
		{name: "bad checksum", statusCode: http.StatusOK, checksum: strings.Repeat("0", 64), wantErr: "SHA-256"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			client := httpDoerFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{
					Status:     fmt.Sprintf("%d status", tc.statusCode),
					StatusCode: tc.statusCode,
					Body:       io.NopCloser(bytes.NewReader(contents)),
				}, nil
			})
			got, err := fetchPinnedFile(context.Background(), client, "https://example.test/schema", tc.checksum)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("fetchPinnedFile() error = %v", err)
				}
				if !bytes.Equal(got, contents) {
					t.Errorf("fetchPinnedFile() = %q, want %q", got, contents)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("fetchPinnedFile() error = %v, want an error containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestUseGoAnnotations(t *testing.T) {
	t.Parallel()

	source := []byte("before\n" + cxxAnnotations + "\nafter\n")
	got, err := useGoAnnotations(source)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte("before\n" + goAnnotations + "\nafter\n")
	if !bytes.Equal(got, want) {
		t.Errorf("useGoAnnotations() = %q, want %q", got, want)
	}

	if _, err := useGoAnnotations([]byte("no annotations")); err == nil {
		t.Fatal("useGoAnnotations() succeeded without the expected annotations")
	}
}

func TestGenerateResolvesRelativeTempDir(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "tmp"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	t.Setenv("TMPDIR", "tmp")

	outputPath := filepath.Join(root, generatedFilename)
	load := func(context.Context) ([]byte, error) {
		return []byte("schema"), nil
	}
	compile := func(_ context.Context, request compileRequest) error {
		for name, path := range map[string]string{
			"output directory": request.outputDir,
			"plugin path":      request.pluginPath,
			"source directory": request.sourceDir,
		} {
			if !filepath.IsAbs(path) {
				t.Errorf("%s %q is not absolute", name, path)
			}
		}
		return os.WriteFile(
			filepath.Join(request.outputDir, generatedFilename),
			[]byte("// generated\n"),
			0o644,
		)
	}

	if err := generate(
		context.Background(),
		options{capnpPath: "capnp", outputPath: outputPath},
		load,
		compile,
	); err != nil {
		t.Fatal(err)
	}
}

func TestResolveCompileRequest(t *testing.T) {
	root := t.TempDir()
	toolsDir := filepath.Join(root, "tools")
	if err := os.Mkdir(toolsDir, 0o755); err != nil {
		t.Fatal(err)
	}

	compilerName := "capnp"
	if runtime.GOOS == "windows" {
		compilerName += ".exe"
	}
	compilerPath := filepath.Join(toolsDir, compilerName)
	if err := os.WriteFile(compilerPath, []byte{}, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)

	got, err := resolveCompileRequest(compileRequest{
		capnpPath:  "." + string(filepath.Separator) + filepath.Join("tools", compilerName),
		outputDir:  filepath.Join("tmp", "output"),
		pluginPath: filepath.Join("tmp", "capnpc-go"),
		sourceDir:  filepath.Join("tmp", "source"),
	})
	if err != nil {
		t.Fatal(err)
	}

	want := compileRequest{
		capnpPath:  compilerPath,
		outputDir:  filepath.Join(root, "tmp", "output"),
		pluginPath: filepath.Join(root, "tmp", "capnpc-go"),
		sourceDir:  filepath.Join(root, "tmp", "source"),
	}
	if got != want {
		t.Errorf("resolveCompileRequest() = %#v, want %#v", got, want)
	}
}

type httpDoerFunc func(*http.Request) (*http.Response, error)

func (f httpDoerFunc) Do(request *http.Request) (*http.Response, error) {
	return f(request)
}
