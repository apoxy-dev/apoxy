// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"slices"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	"github.com/apoxy-dev/apoxy/pkg/vpc/transport/peerconn"
	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// extraConn is the process of one extra QUIC connection of a home session in
// QUIC mode: a connection from the agent socket to the same relay with the cert
// in use, whose Session call joins the attachment. One that ends is dialed again.
type extraConn struct {
	a      *Agent
	mb, up *mailbox
	i      int
	d      *dialed // The session connection.
	id     string  // Attachment ID.
	pc     *peerconn.Conn
	ctx    context.Context
	cancel context.CancelFunc
	tasks  int
	ending bool
	qc     quic.Connection // Nil when the connection is down.
	retry  *time.Timer
	wait   time.Duration
}

// Messages of an extra connection.
type (
	extraUp struct {
		ec *extraConn
		qc quic.Connection
	}
	extraDown  struct{ ec *extraConn }
	extraEnded struct{ ec *extraConn }
	// extraDialed is the result of the dial task.
	extraDialed struct {
		qc  quic.Connection
		st  rpc.BidiStreamClient[dp.SessionRequest, dp.SessionResponse]
		err error
	}
	// extraLost tells that the stream or the datagram reader of qc ended.
	extraLost struct{ qc quic.Connection }
)

// startExtras starts extra connections 1 to quicConns-1 of a home session in
// QUIC mode.
func (s *session) startExtras() {
	if !s.attached || len(s.cur) > 0 || s.ending {
		return
	}
	for i := 1; i < quicConns; i++ {
		ec := &extraConn{a: s.a, mb: newMailbox(), up: s.mb, i: i, d: s.d, id: s.id, pc: s.pc, wait: minBackoff}
		ec.ctx, ec.cancel = context.WithCancel(s.ctx)
		s.cur = append(s.cur, ec)
		s.extraConns[ec] = true
		go ec.run()
	}
}

// stopExtras ends the extra connections of the session.
func (s *session) stopExtras() {
	for _, ec := range s.cur {
		ec.mb.send(endMsg{})
		_ = s.pc.SetExtra(ec.i, nil)
	}
	s.cur = nil
}

// extraUp gives the packet connection of the session an extra connection that opened.
func (s *session) extraUp(m extraUp) {
	if !slices.Contains(s.cur, m.ec) {
		go func() { _ = m.qc.CloseWithError(0, "") }()
		return
	}
	if err := s.pc.SetExtra(m.ec.i, m.qc); err != nil {
		m.ec.mb.send(endMsg{})
	}
}

func (ec *extraConn) task(f func() any) {
	ec.tasks++
	mb := ec.mb
	go func() { mb.send(taskDone{f()}) }()
}

func (ec *extraConn) run() {
	ec.dial()
	for !ec.ending || ec.tasks > 0 {
		select {
		case <-ec.mb.wake:
			for _, m := range ec.mb.take() {
				ec.handle(m)
			}
		case <-timerC(ec.retry):
			ec.retry = nil
			if !ec.ending {
				ec.dial()
			}
		}
	}
	ec.up.send(extraEnded{ec})
}

func (ec *extraConn) handle(m any) {
	switch m := m.(type) {
	case taskDone:
		ec.tasks--
		ec.handle(m.m)
	case endMsg:
		if ec.ending {
			return
		}
		ec.ending = true
		ec.cancel()
		if ec.retry != nil {
			ec.retry.Stop()
			ec.retry = nil
		}
		ec.close()
	case extraDialed:
		switch {
		case m.err != nil && ec.ending:
		case m.err != nil:
			slog.Warn("Failed to open an extra relay connection", "relay", ec.d.ep.addr, "extra", ec.i, "error", m.err)
			ec.backoff()
		case ec.ending:
			qc := m.qc
			go func() { _ = qc.CloseWithError(0, "") }()
		default:
			ec.wait, ec.qc = minBackoff, m.qc
			ec.up.send(extraUp{ec, m.qc})
			// The relay ends the call when the connection or its session ends.
			st, qc, mb, ctx, pc := m.st, m.qc, ec.mb, ec.ctx, ec.pc
			ec.task(func() any {
				_, _ = st.Recv()
				return extraLost{qc}
			})
			go func() {
				pc.Receive(ctx, qc)
				mb.send(extraLost{qc})
			}()
		}
	case extraLost:
		if m.qc != ec.qc || ec.ending {
			return
		}
		ec.close()
		ec.up.send(extraDown{ec})
		ec.backoff()
	}
}

// close closes the extra connection in its own goroutine.
func (ec *extraConn) close() {
	if qc := ec.qc; qc != nil {
		ec.qc = nil
		go func() { _ = qc.CloseWithError(0, "") }()
	}
}

func (ec *extraConn) backoff() {
	ec.retry = time.NewTimer(rand.N(ec.wait) + 1)
	ec.wait = min(2*ec.wait, maxBackoff)
}

// dial starts the dial task of the extra connection.
func (ec *extraConn) dial() {
	a, d, i, id, ctx := ec.a, ec.d, ec.i, ec.id, ec.ctx
	ec.task(func() any {
		dctx, cancel := context.WithTimeout(ctx, openTimeout)
		defer cancel()
		qc, err := a.cfg.Transport.Dial(dctx, d.qc.RemoteAddr(), &tls.Config{
			MinVersion:           tls.VersionTLS13,
			RootCAs:              d.roots,
			ServerName:           d.name,
			NextProtos:           []string{dp.ALPNRelay},
			GetClientCertificate: a.cfg.Identity.GetClientCertificate,
		}, a.quicCfg)
		if err != nil {
			return extraDialed{err: err}
		}
		// A relay that does not answer in time ends the dial.
		stop := context.AfterFunc(dctx, func() { _ = qc.CloseWithError(0, "extra relay connection did not open in time") })
		defer stop()
		st, err := dp.NewRelayClient(rpc.NewConn(qc, nil)).Session(ctx)
		if err == nil {
			err = st.Send(&dp.SessionRequest{Msg: &dp.SessionRequest_Hello{Hello: &dp.Hello{
				Mode:    dp.Mode_MODE_QUIC,
				Shard:   &dp.Shard{AttachmentId: id, Index: uint32(i)},
				Version: a.ver,
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
			go func() { _ = qc.CloseWithError(0, "") }()
			return extraDialed{err: err}
		}
		return extraDialed{qc: qc, st: st}
	})
}
