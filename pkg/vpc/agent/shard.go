// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// keepShards keeps shards 1 to n-1 of rc on its packet connection until rc
// or its connection closes. A shard that ends is dialed again.
func (rc *relayConn) keepShards(n int) {
	// A shard dial after the session ends gets no session at the relay.
	ctx, cancel := context.WithCancel(rc.ctx)
	defer cancel()
	stop := context.AfterFunc(rc.qc.Context(), cancel)
	defer stop()
	var wg sync.WaitGroup
	for i := 1; i < n; i++ {
		wg.Go(func() { rc.keepShard(ctx, i) })
	}
	wg.Wait()
}

func (rc *relayConn) keepShard(ctx context.Context, i int) {
	backoff := minBackoff
	for ctx.Err() == nil {
		octx, cancel := context.WithTimeout(ctx, openTimeout)
		qc, err := rc.dialShard(octx, i)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Warn("Failed to open a relay shard", "relay", rc.addr, "shard", i, "error", err)
		} else {
			backoff = minBackoff
			if err := rc.pc.SetShard(i, qc); err != nil {
				_ = qc.CloseWithError(0, "")
				return
			}
			select {
			case <-qc.Context().Done():
			case <-ctx.Done():
				_ = qc.CloseWithError(0, "")
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(rand.N(backoff) + 1):
		}
		backoff = min(2*backoff, maxBackoff)
	}
}

// dialShard opens shard i of rc: a connection from the agent socket to the
// same relay with the same cert, whose Session call joins the attachment.
func (rc *relayConn) dialShard(ctx context.Context, i int) (quic.Connection, error) {
	a := rc.a
	qc, err := a.cfg.Transport.Dial(ctx, rc.qc.RemoteAddr(), &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      rc.roots,
		ServerName:   rc.name,
		NextProtos:   []string{dp.ALPNRelay},
		Certificates: []tls.Certificate{*rc.cred.TLSCertificate()},
	}, relayQUIC)
	if err != nil {
		return nil, err
	}
	// A relay that does not answer in time ends the dial.
	stop := context.AfterFunc(ctx, func() { _ = qc.CloseWithError(0, "relay shard did not open in time") })
	defer stop()
	st, err := dp.NewRelayClient(rpc.NewConn(qc, nil)).Session(context.Background())
	if err == nil {
		err = st.Send(&dp.SessionRequest{Msg: &dp.SessionRequest_Hello{Hello: &dp.Hello{
			Mode:  dp.Mode_MODE_QUIC,
			Shard: &dp.Shard{AttachmentId: rc.claims.GetAttachmentId(), Index: uint32(i)},
		}}})
	}
	var m *dp.SessionResponse
	if err == nil {
		m, err = st.Recv()
	}
	if err == nil && m.GetWelcome() == nil {
		err = fmt.Errorf("relay sent %T before Welcome", m.GetMsg())
	}
	if err != nil {
		_ = qc.CloseWithError(0, "")
		return nil, err
	}
	// The relay ends the call when the shard or its session ends.
	go func() {
		_, _ = st.Recv()
		_ = qc.CloseWithError(0, "")
	}()
	return qc, nil
}
