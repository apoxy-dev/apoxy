// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mtuNetworks gives one network with the MTU of the VPC network object.
type mtuNetworks uint32

func (m mtuNetworks) Network(string, string) (Network, error) {
	return Network{ID: testVNI, MTU: uint32(m)}, nil
}

// TestNetworkMTU checks the MTU that the relay gives to agents for the MTU of
// the VPC network object, which can be from before a spec check.
func TestNetworkMTU(t *testing.T) {
	cases := []struct {
		name      string
		mtu, want uint32
	}{
		{name: "unset", mtu: 0, want: 1280},
		{name: "lowest", mtu: 1280, want: 1280},
		{name: "in the range", mtu: 1300, want: 1300},
		{name: "largest", mtu: 1412, want: 1412},
		{name: "one above the largest", mtu: 1413, want: 1412},
		{name: "far above the largest", mtu: 9000, want: 1412},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := &Server{Networks: mtuNetworks(tc.mtu)}
			n, err := srv.network(vpcA)
			require.NoError(t, err)
			assert.Equal(t, tc.want, n.MTU)
			assert.Equal(t, uint32(testVNI), n.ID)
		})
	}
}
