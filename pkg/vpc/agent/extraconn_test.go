// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

// TestKeepExtras checks that the agent dials an extra connection again when the relay closes
// it, that data goes the whole time, and that the extra connections end with the agent.
func TestKeepExtras(t *testing.T) {
	w := newWorld(t)
	r := w.relay(t, "relay-1")
	a := w.agent(t, "a", r, agentOptions{mode: TransportQUIC})
	b := w.agent(t, "b", r, agentOptions{})
	ea, eb := a.attached(t), b.attached(t)
	echo(t, b.stack, eb.addr, 9000)
	conns := func() []quic.Connection { return r.agentConns(a.tr.Conn.LocalAddr(), true) }
	require.Eventually(t, func() bool { return len(conns()) == quicConns }, 10*time.Second, 10*time.Millisecond,
		"the relay has the session and its extra connections")
	ping(t, a.stack, ea.addr, eb.addr, 9000, "before")

	extra := conns()[1]
	_ = extra.CloseWithError(0, "test closes the extra connection")
	ping(t, a.stack, ea.addr, eb.addr, 9000, "with no extra connection 1")
	require.Eventually(t, func() bool {
		cs := conns()
		return len(cs) == quicConns && cs[1] != extra
	}, 10*time.Second, 10*time.Millisecond, "the agent dials extra connection 1 again")
	ping(t, a.stack, ea.addr, eb.addr, 9000, "after")

	a.stop()
	require.Eventually(t, func() bool { return len(conns()) == 0 }, 5*time.Second, 10*time.Millisecond,
		"the extra connections end with the agent")
}
