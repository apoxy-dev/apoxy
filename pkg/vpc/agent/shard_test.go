// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

func TestKeepShards(t *testing.T) {
	w := newWorld(t)
	ta := w.agent(t, "a", w.relay(t, "relay-1"), agentOptions{})
	ta.attached(t)
	ta.a.mu.Lock()
	rc := ta.a.rc
	ta.a.mu.Unlock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		rc.keepShards(peerconn.MaxShards)
	}()
	live := func() bool { return rc.pc.Shards() == peerconn.MaxShards }
	require.Eventually(t, live, 10*time.Second, 10*time.Millisecond)

	// The relay closes shard 1 when this test joins a new shard 1. The agent
	// dials it again, and that join closes the test shard.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	qc, err := rc.dialShard(ctx, 1)
	require.NoError(t, err)
	select {
	case <-qc.Context().Done():
	case <-time.After(10 * time.Second):
		t.Fatal("agent did not dial shard 1 again in 10 s")
	}
	require.Eventually(t, live, 10*time.Second, 10*time.Millisecond)

	// A join for another attachment fails.
	bad := &relayConn{a: rc.a, qc: rc.qc, cred: rc.cred, name: rc.name, claims: &dp.GrantClaims{AttachmentId: "0123"}}
	_, err = bad.dialShard(ctx, 1)
	assert.Equal(t, rpc.NotFound, rpc.CodeOf(err), "error: %v", err)

	// The shards end with the session.
	ta.stop()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("shards did not end with the session in 10 s")
	}
}
