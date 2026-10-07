package alpha

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVPCCommandsAreVisible(t *testing.T) {
	for _, name := range []string{"connect", "enroll"} {
		t.Run(name, func(t *testing.T) {
			c, _, err := Cmd().Find([]string{"vpc", name})
			require.NoError(t, err)
			require.Equal(t, name, c.Name())
			require.Equal(t, "vpc", c.Parent().Name())
			require.True(t, c.IsAvailableCommand())
		})
	}
}
