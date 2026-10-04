package alpha

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVPCConnectIsVisible(t *testing.T) {
	c, _, err := Cmd().Find([]string{"vpc", "connect"})
	require.NoError(t, err)
	require.Equal(t, "connect", c.Name())
	require.Equal(t, "vpc", c.Parent().Name())
	require.True(t, c.IsAvailableCommand())
}
