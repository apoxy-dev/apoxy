package resource

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	"github.com/apoxy-dev/apoxy/pretty"
	"github.com/apoxy-dev/apoxy/rest"
)

// fakeObj is a minimal Object implementation for testing.
type fakeObj struct {
	metav1.ObjectMeta `json:"metadata"`
	metav1.TypeMeta   `json:",inline"`
}

func (f *fakeObj) DeepCopyObject() runtime.Object { return f }
func (f *fakeObj) GetObjectKind() schema.ObjectKind { return &f.TypeMeta }

// fakeList implements runtime.Object.
type fakeList struct {
	metav1.TypeMeta `json:",inline"`
	Items           []*fakeObj
}

func (f *fakeList) DeepCopyObject() runtime.Object { return f }
func (f *fakeList) GetObjectKind() schema.ObjectKind { return &f.TypeMeta }

// fakeClient captures the ListOptions passed to List and the names passed
// to Get and Delete.
type fakeClient struct {
	lastListOpts metav1.ListOptions
	lastGetName  string
	deleted      []string
}

func (f *fakeClient) Get(_ context.Context, name string, _ metav1.GetOptions) (*fakeObj, error) {
	f.lastGetName = name
	return &fakeObj{
		ObjectMeta: metav1.ObjectMeta{Name: name},
	}, nil
}

func (f *fakeClient) List(_ context.Context, opts metav1.ListOptions) (*fakeList, error) {
	f.lastListOpts = opts
	return &fakeList{
		Items: []*fakeObj{
			{ObjectMeta: metav1.ObjectMeta{Name: "item1"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "item2"}},
		},
	}, nil
}

func (f *fakeClient) Create(_ context.Context, obj *fakeObj, _ metav1.CreateOptions) (*fakeObj, error) {
	return obj, nil
}

func (f *fakeClient) Delete(_ context.Context, name string, _ metav1.DeleteOptions) error {
	f.deleted = append(f.deleted, name)
	return nil
}

func (f *fakeClient) Patch(_ context.Context, _ string, _ types.PatchType, _ []byte, _ metav1.PatchOptions, _ ...string) (*fakeObj, error) {
	return &fakeObj{}, nil
}

func buildTestCommand(fc *fakeClient, listFlags func(cmd *cobra.Command) func() string) *cobra.Command {
	r := &ResourceCommand[*fakeObj, *fakeList]{
		Use:      "fake",
		Short:    "Fake resource",
		KindName: "fake",
		ClientFunc: func(_ *rest.APIClient) ResourceClient[*fakeObj, *fakeList] {
			return fc
		},
		CustomPrinter: &CustomPrinterConfig[*fakeObj, *fakeList]{
			Header:   func(_ bool) pretty.Header { return pretty.Header{"NAME"} },
			BuildRow: func(_ *fakeObj, _ bool) []interface{} { return []interface{}{"test"} },
			GetItems: func(l *fakeList) []*fakeObj { return l.Items },
		},
		ListFlags: listFlags,
	}
	return r.Build()
}

func executeCommand(cmd *cobra.Command, args ...string) error {
	cmd.SetArgs(args)
	return cmd.Execute()
}

func TestFieldSelectorFlag(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		wantFS   string
	}{
		{
			name:   "no flags on root",
			args:   []string{},
			wantFS: "",
		},
		{
			name:   "field-selector on root",
			args:   []string{"--field-selector", "spec.zone=example.com"},
			wantFS: "spec.zone=example.com",
		},
		{
			name:   "field-selector on list subcommand",
			args:   []string{"list", "--field-selector", "status.phase=Active"},
			wantFS: "status.phase=Active",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fc := &fakeClient{}
			cmd := buildTestCommand(fc, nil)
			err := executeCommand(cmd, tt.args...)
			require.NoError(t, err)
			assert.Equal(t, tt.wantFS, fc.lastListOpts.FieldSelector)
		})
	}
}

// captureStdout runs fn while capturing os.Stdout and returns what was written.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	orig := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = orig }()

	fn()
	w.Close()

	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	require.NoError(t, err)
	return buf.String()
}

func TestOutputFormat(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		checkJSON bool
		checkYAML bool
	}{
		{
			name:      "get -o json",
			args:      []string{"get", "my-resource", "-o", "json"},
			checkJSON: true,
		},
		{
			name:      "list -o json via root",
			args:      []string{"-o", "json"},
			checkJSON: true,
		},
		{
			name:      "list -o json via subcommand",
			args:      []string{"list", "-o", "json"},
			checkJSON: true,
		},
		{
			name:      "get -o yaml",
			args:      []string{"get", "my-resource", "-o", "yaml"},
			checkYAML: true,
		},
		{
			name:      "list -o yaml via root",
			args:      []string{"-o", "yaml"},
			checkYAML: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fc := &fakeClient{}
			cmd := buildTestCommand(fc, nil)

			out := captureStdout(t, func() {
				err := executeCommand(cmd, tt.args...)
				require.NoError(t, err)
			})

			if tt.checkJSON {
				assert.True(t, json.Valid([]byte(out)), "output should be valid JSON: %s", out)
			}
			if tt.checkYAML {
				assert.True(t, strings.Contains(out, "name:") || strings.Contains(out, "items:"),
					"output should contain YAML fields: %s", out)
				assert.False(t, json.Valid([]byte(out)), "YAML output should not be valid JSON")
			}
		})
	}
}

func TestOutputFormatDefaultIsTable(t *testing.T) {
	fc := &fakeClient{}
	cmd := buildTestCommand(fc, nil)

	out := captureStdout(t, func() {
		err := executeCommand(cmd, "get", "my-resource")
		require.NoError(t, err)
	})

	// Table output contains the header from CustomPrinter.
	assert.Contains(t, out, "NAME")
	assert.False(t, json.Valid([]byte(out)), "default output should not be JSON")
}

func TestResolveName(t *testing.T) {
	// A resolver that maps a bare FQDN to its internal suffixed name and
	// rejects names it doesn't know, mirroring the domain command's resolver.
	resolver := func(_ context.Context, _ *rest.APIClient, arg string) (string, error) {
		switch arg {
		case "cname.example.com":
			return "cname.example.com--ref", nil
		case "cname.example.com--ref":
			return arg, nil
		default:
			return "", fmt.Errorf("fake %q not found", arg)
		}
	}
	build := func(fc *fakeClient) *cobra.Command {
		r := &ResourceCommand[*fakeObj, *fakeList]{
			Use:      "fake",
			Short:    "Fake resource",
			KindName: "fake",
			ClientFunc: func(_ *rest.APIClient) ResourceClient[*fakeObj, *fakeList] {
				return fc
			},
			CustomPrinter: &CustomPrinterConfig[*fakeObj, *fakeList]{
				Header:   func(_ bool) pretty.Header { return pretty.Header{"NAME"} },
				BuildRow: func(_ *fakeObj, _ bool) []interface{} { return []interface{}{"test"} },
				GetItems: func(l *fakeList) []*fakeObj { return l.Items },
			},
			ResolveName: resolver,
		}
		return r.Build()
	}

	cases := []struct {
		name        string
		args        []string
		wantErr     string
		wantGetName string
		wantDeleted []string
	}{
		{
			name:        "get resolves bare name",
			args:        []string{"get", "cname.example.com"},
			wantGetName: "cname.example.com--ref",
		},
		{
			name:        "delete resolves bare name",
			args:        []string{"delete", "cname.example.com"},
			wantDeleted: []string{"cname.example.com--ref"},
		},
		{
			name:        "delete passes through full name",
			args:        []string{"delete", "cname.example.com--ref"},
			wantDeleted: []string{"cname.example.com--ref"},
		},
		{
			name:    "get unknown name fails",
			args:    []string{"get", "nope.example.com"},
			wantErr: "not found",
		},
		{
			name:    "delete resolves all names before deleting any",
			args:    []string{"delete", "cname.example.com", "nope.example.com"},
			wantErr: "not found",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fc := &fakeClient{}
			cmd := build(fc)
			var err error
			captureStdout(t, func() { err = executeCommand(cmd, tc.args...) })
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
			} else {
				require.NoError(t, err)
			}
			if tc.wantGetName != "" {
				assert.Equal(t, tc.wantGetName, fc.lastGetName)
			}
			assert.Equal(t, tc.wantDeleted, fc.deleted)
		})
	}
}

func TestListFlagsMerge(t *testing.T) {
	zoneListFlags := func(cmd *cobra.Command) func() string {
		var zone string
		cmd.Flags().StringVar(&zone, "zone", "", "Filter by zone.")
		return func() string {
			if zone != "" {
				return "spec.zone=" + zone
			}
			return ""
		}
	}

	tests := []struct {
		name   string
		args   []string
		wantFS string
	}{
		{
			name:   "zone only on root",
			args:   []string{"--zone", "example.com"},
			wantFS: "spec.zone=example.com",
		},
		{
			name:   "zone only on list",
			args:   []string{"list", "--zone", "example.com"},
			wantFS: "spec.zone=example.com",
		},
		{
			name:   "field-selector and zone on root",
			args:   []string{"--field-selector", "status.phase=Active", "--zone", "example.com"},
			wantFS: "status.phase=Active,spec.zone=example.com",
		},
		{
			name:   "field-selector and zone on list",
			args:   []string{"list", "--field-selector", "status.phase=Active", "--zone", "example.com"},
			wantFS: "status.phase=Active,spec.zone=example.com",
		},
		{
			name:   "zone not set merges nothing",
			args:   []string{"--field-selector", "status.phase=Active"},
			wantFS: "status.phase=Active",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fc := &fakeClient{}
			cmd := buildTestCommand(fc, zoneListFlags)
			err := executeCommand(cmd, tt.args...)
			require.NoError(t, err)
			assert.Equal(t, tt.wantFS, fc.lastListOpts.FieldSelector)
		})
	}
}
