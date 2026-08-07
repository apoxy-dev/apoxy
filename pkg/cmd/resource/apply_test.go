package resource

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSplitYAMLDocuments(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "single document",
			input: "kind: Proxy\n",
			want:  []string{"kind: Proxy\n"},
		},
		{
			name:  "two documents",
			input: "kind: Proxy\n---\nkind: Backend\n",
			want:  []string{"kind: Proxy", "\nkind: Backend\n"},
		},
		{
			name:  "leading comment before first separator",
			input: "# comment\n---\nkind: Proxy\n---\nkind: Backend\n",
			want:  []string{"\nkind: Proxy", "\nkind: Backend\n"},
		},
		{
			name:  "comment-only section between documents",
			input: "kind: Proxy\n---\n# just a comment\n---\nkind: Backend\n",
			want:  []string{"kind: Proxy", "\nkind: Backend\n"},
		},
		{
			name:  "blank sections",
			input: "---\nkind: Proxy\n---\n\n---\nkind: Backend\n---\n",
			want:  []string{"---\nkind: Proxy", "\nkind: Backend"},
		},
		{
			name:  "leading document marker with only comments",
			input: "---\n# header comment\n---\nkind: Proxy\n",
			want:  []string{"\nkind: Proxy\n"},
		},
		{
			name:  "only comments and separators",
			input: "# a\n---\n# b\n",
			want:  nil,
		},
		{
			name:  "empty input",
			input: "",
			want:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SplitYAMLDocuments([]byte(tt.input))
			require.Len(t, got, len(tt.want))
			for i, doc := range got {
				assert.Equal(t, tt.want[i], string(doc))
			}
		})
	}
}
