// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// shardWorld is a relay with one owner session that has an attachment.
type shardWorld struct {
	h     *harness
	ca    *testCA
	cert  tls.Certificate
	owner agent
	sync  syncStream
	att   string
}

func newShardWorld(t *testing.T) *shardWorld {
	t.Helper()
	ca := newCA(t)
	w := &shardWorld{h: newHarness(t, ca), ca: ca, cert: ca.agentCert(t, vpcA, "laptop")}
	w.owner = w.h.mustDial(t, w.cert)
	w.sync, _, _ = open(t, w.owner)
	w.att = attach(t, w.owner, &dp.AttachRequest{Vpc: ref(vpcA), Name: "laptop"}).AttachmentId
	return w
}

// dial opens a connection with cert from the socket of the owner, as a
// shard does.
func (w *shardWorld) dial(t *testing.T, cert tls.Certificate) agent {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tc := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{dp.ALPNRelay}, Certificates: []tls.Certificate{cert}}
	qc, err := w.owner.tr.Dial(ctx, w.h.ln.Addr(), tc, &quic.Config{EnableDatagrams: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = qc.CloseWithError(0, "") })
	return agent{c: dp.NewRelayClient(rpc.NewConn(qc, nil)), qc: qc, tr: w.owner.tr, src: w.owner.src}
}

// join sends the shard Hello on a and returns the call after Welcome.
func join(t *testing.T, a agent, att string, index uint32) (syncStream, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	st, err := a.c.Session(ctx)
	require.NoError(t, err)
	require.NoError(t, st.Send(&dp.SessionRequest{Msg: &dp.SessionRequest_Hello{Hello: &dp.Hello{
		Mode:  dp.Mode_MODE_QUIC,
		Shard: &dp.Shard{AttachmentId: att, Index: index},
	}}}))
	m, err := st.Recv()
	if err != nil {
		return nil, err
	}
	require.NotNil(t, m.GetWelcome(), "first message: %v", m)
	return st, nil
}

func TestShardJoinRefused(t *testing.T) {
	cases := []struct {
		name string
		// prep returns the connection, attachment and index of the join.
		prep func(t *testing.T, w *shardWorld) (agent, string, uint32)
		code rpc.Code
	}{
		{
			name: "index 0",
			prep: func(t *testing.T, w *shardWorld) (agent, string, uint32) { return w.dial(t, w.cert), w.att, 0 },
			code: rpc.InvalidArgument,
		},
		{
			name: "index not below the limit",
			prep: func(t *testing.T, w *shardWorld) (agent, string, uint32) {
				return w.dial(t, w.cert), w.att, peerconn.MaxShards
			},
			code: rpc.InvalidArgument,
		},
		{
			name: "unknown attachment",
			prep: func(t *testing.T, w *shardWorld) (agent, string, uint32) { return w.dial(t, w.cert), "0123", 1 },
			code: rpc.NotFound,
		},
		{
			name: "other agent identity",
			prep: func(t *testing.T, w *shardWorld) (agent, string, uint32) {
				return w.dial(t, w.ca.agentCert(t, vpcA, "other")), w.att, 1
			},
			code: rpc.PermissionDenied,
		},
		{
			name: "other VPC",
			prep: func(t *testing.T, w *shardWorld) (agent, string, uint32) {
				return w.dial(t, w.ca.agentCert(t, vpcB, "laptop")), w.att, 1
			},
			code: rpc.NotFound,
		},
		{
			name: "owner closed",
			prep: func(t *testing.T, w *shardWorld) (agent, string, uint32) {
				s := w.h.session(t, w.owner)
				require.NoError(t, w.owner.qc.CloseWithError(0, ""))
				require.Eventually(t, func() bool {
					w.h.r.mu.RLock()
					defer w.h.r.mu.RUnlock()
					return s.closed
				}, 5*time.Second, 5*time.Millisecond)
				return w.dial(t, w.cert), w.att, 1
			},
			code: rpc.NotFound,
		},
		{
			name: "connection has a Session call",
			prep: func(t *testing.T, w *shardWorld) (agent, string, uint32) {
				a := w.dial(t, w.cert)
				open(t, a)
				return a, w.att, 1
			},
			code: rpc.FailedPrecondition,
		},
		{
			name: "connection has routes",
			prep: func(t *testing.T, w *shardWorld) (agent, string, uint32) {
				a := w.dial(t, w.cert)
				attach(t, a, &dp.AttachRequest{Vpc: ref(vpcA), Name: "laptop"})
				return a, w.att, 1
			},
			code: rpc.FailedPrecondition,
		},
		{
			name: "connection is a shard",
			prep: func(t *testing.T, w *shardWorld) (agent, string, uint32) {
				a := w.dial(t, w.cert)
				_, err := join(t, a, w.att, 1)
				require.NoError(t, err)
				return a, w.att, 2
			},
			code: rpc.FailedPrecondition,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := newShardWorld(t)
			a, att, index := tc.prep(t, w)
			_, err := join(t, a, att, index)
			assert.Equal(t, tc.code, rpc.CodeOf(err), "error: %v", err)
		})
	}
}

func TestShards(t *testing.T) {
	w := newShardWorld(t)
	r := w.h.r
	owner := w.h.session(t, w.owner)
	shards := make([]agent, peerconn.MaxShards)
	for i := 1; i < peerconn.MaxShards; i++ {
		shards[i] = w.dial(t, w.cert)
		_, err := join(t, shards[i], w.att, uint32(i))
		require.NoError(t, err)
	}

	// The shards hang off the owner, outside the domain, with no source
	// address. The owner keeps the source address of the socket.
	check := func() {
		t.Helper()
		r.mu.RLock()
		defer r.mu.RUnlock()
		assert.Same(t, owner, r.bySource[w.owner.src])
		for i := 1; i < peerconn.MaxShards; i++ {
			s := owner.shards[i]
			require.NotNil(t, s, "shard %d", i)
			assert.Same(t, owner, s.shardOf)
			assert.False(t, s.addr.IsValid())
			assert.NotContains(t, r.domains[vpcA].members, s)
		}
	}
	check()
	r.Sweep(time.Now())
	check()

	// A shard takes no calls after the join.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := shards[1].c.Attach(ctx, &dp.AttachRequest{Vpc: ref(vpcA), Name: "laptop"})
	assert.Equal(t, rpc.FailedPrecondition, rpc.CodeOf(err), "error: %v", err)

	// A new shard 2 replaces the old one, which closes.
	old := shards[2]
	shards[2] = w.dial(t, w.cert)
	_, err = join(t, shards[2], w.att, 2)
	require.NoError(t, err)
	closeCode(t, old.qc)
	check()

	// A shard that closes leaves its owner.
	require.NoError(t, shards[3].qc.CloseWithError(0, ""))
	require.Eventually(t, func() bool {
		r.mu.RLock()
		defer r.mu.RUnlock()
		return owner.shards[3] == nil
	}, 5*time.Second, 5*time.Millisecond)

	// The shards close with their owner, and the relay forgets them all.
	require.NoError(t, w.owner.qc.CloseWithError(0, ""))
	closeCode(t, shards[1].qc)
	closeCode(t, shards[2].qc)
	require.Eventually(t, func() bool {
		r.mu.RLock()
		defer r.mu.RUnlock()
		return len(r.sessions) == 0 && len(r.byConn) == 0 && len(r.bySource) == 0
	}, 5*time.Second, 5*time.Millisecond)
}

// TestShardSource checks that the owner keeps the source address of its
// socket when a shard from that socket comes and goes.
func TestShardSource(t *testing.T) {
	w := newShardWorld(t)
	owner := w.h.session(t, w.owner)
	a := w.dial(t, w.cert)
	_, err := join(t, a, w.att, 1)
	require.NoError(t, err)
	require.NoError(t, a.qc.CloseWithError(0, ""))
	require.Eventually(t, func() bool {
		w.h.r.mu.RLock()
		defer w.h.r.mu.RUnlock()
		return len(w.h.r.sessions) == 1
	}, 5*time.Second, 5*time.Millisecond)
	w.h.r.mu.RLock()
	defer w.h.r.mu.RUnlock()
	assert.Same(t, owner, w.h.r.bySource[w.owner.src])
}
