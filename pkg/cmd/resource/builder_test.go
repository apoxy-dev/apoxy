package resource

import (
	"context"
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

// fakeClient captures the ListOptions passed to List.
type fakeClient struct {
	lastListOpts metav1.ListOptions
}

func (f *fakeClient) Get(_ context.Context, _ string, _ metav1.GetOptions) (*fakeObj, error) {
	return &fakeObj{}, nil
}

func (f *fakeClient) List(_ context.Context, opts metav1.ListOptions) (*fakeList, error) {
	f.lastListOpts = opts
	return &fakeList{}, nil
}

func (f *fakeClient) Create(_ context.Context, obj *fakeObj, _ metav1.CreateOptions) (*fakeObj, error) {
	return obj, nil
}

func (f *fakeClient) Delete(_ context.Context, _ string, _ metav1.DeleteOptions) error {
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
