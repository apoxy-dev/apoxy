//go:build linux

package router

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	utiliptables "k8s.io/kubernetes/pkg/util/iptables"
	fakeiptables "k8s.io/kubernetes/pkg/util/iptables/testing"
)

func TestOverlayPortFilters(t *testing.T) {
	v4 := fakeiptables.NewFake()
	v6 := fakeiptables.NewIPv6Fake()
	ports := []uint16{18080, 19090}
	chainName := overlayPortFilterChain("apoxy0")

	require.NoError(t, ensureOverlayPortFilters(v4, v6, "apoxy0", ports))

	for _, ipt := range []*fakeiptables.FakeIPTables{v4, v6} {
		input, err := ipt.Dump.GetChain(utiliptables.TableFilter, utiliptables.ChainInput)
		require.NoError(t, err)
		require.Len(t, input.Rules, 1)
		require.Contains(t, input.Rules[0].Raw, "-i apoxy0")
		require.Contains(t, input.Rules[0].Raw, "--comment "+overlayPortFilterComment)
		require.Contains(t, input.Rules[0].Raw, "-j "+string(chainName))

		chain, err := ipt.Dump.GetChain(utiliptables.TableFilter, chainName)
		require.NoError(t, err)
		require.Len(t, chain.Rules, 2)
		for _, port := range []string{"18080", "19090"} {
			require.True(t, strings.Contains(ipt.Dump.String(), "-p tcp --dport "+port))
		}
		require.Contains(t, ipt.Dump.String(), "-j REJECT --reject-with tcp-reset")
	}

	// Reconciliation replaces stale ports without adding a second INPUT jump.
	require.NoError(t, ensureOverlayPortFilters(v4, v6, "apoxy0", []uint16{20000}))
	for _, ipt := range []*fakeiptables.FakeIPTables{v4, v6} {
		input, err := ipt.Dump.GetChain(utiliptables.TableFilter, utiliptables.ChainInput)
		require.NoError(t, err)
		require.Len(t, input.Rules, 1)
		chain, err := ipt.Dump.GetChain(utiliptables.TableFilter, chainName)
		require.NoError(t, err)
		require.Len(t, chain.Rules, 1)
		require.Contains(t, chain.Rules[0].Raw, "--dport 20000")
	}

	require.NoError(t, deleteOverlayPortFilters(v4, v6, "apoxy0"))
	for _, ipt := range []*fakeiptables.FakeIPTables{v4, v6} {
		input, err := ipt.Dump.GetChain(utiliptables.TableFilter, utiliptables.ChainInput)
		require.NoError(t, err)
		require.Empty(t, input.Rules)
		exists, err := ipt.ChainExists(utiliptables.TableFilter, chainName)
		require.NoError(t, err)
		require.False(t, exists)
	}
}
