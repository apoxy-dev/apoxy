// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/apoxy-dev/softpsp/keys"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dpv1 "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// msOpen is what a member gave in Open.
type msOpen struct {
	name string
	ref  *dpv1.RelayRef
	ver  *dpv1.Version
	psp  netip.AddrPort // The data address of the member.
}

// Events of MS from the handlers of its connection and from its tasks.
type (
	// msIncoming is an incoming Presence call of tenant, whose first message is first. done gets
	// the status of the call.
	msIncoming struct {
		st     presenceServer
		tenant string
		first  *dpv1.PresenceUpdate
		done   chan error
	}
	// msTrunkKeys is a TrunkKeys call of the member.
	msTrunkKeys struct {
		req keys.Request
		res chan callResult
	}
	msOpened struct {
		open msOpen
		err  error
	}
	msServed struct{}
	msEnd    struct {
		code dpv1.MeshCloseCode
		msg  string
	}
)

// Messages of MS to M.
type (
	msUp      struct{ ms *msProc }
	mIncoming struct {
		ms *msProc
		msIncoming
	}
	mTrunkApply struct {
		ms *msProc
		msTrunkKeys
	}
	// msEnded tells M that the MS ended. restart is true when the member closed it with RESTART.
	msEnded struct {
		ms      *msProc
		up      bool
		restart bool
		err     error
	}
)

// msProc is the process MS of one mesh session: the QUIC connection and its handlers.
type msProc struct {
	r      *Router
	mbox   *mailbox // The mailbox of M.
	box    *mailbox
	c      *meshConn
	name   string
	n      uint64 // The MS number: the session of the trunk port.
	ctx    context.Context
	cancel context.CancelFunc
	open   msOpen
	up     bool
	served bool // The serve task of a dialed connection ended.
	err    error
}

// startMS starts the MS of the connection c with the member name. A connection that this relay
// accepted passed Open, and open has its data.
func startMS(r *Router, mbox *mailbox, c *meshConn, name string, n uint64, open msOpen) *msProc {
	ctx, cancel := context.WithCancel(context.Background())
	ms := &msProc{r: r, mbox: mbox, box: newMailbox(0), c: c, name: name, n: n, ctx: ctx, cancel: cancel, open: open, served: !c.dialer}
	c.ms.Store(ms)
	go ms.run()
	return ms
}

func (ms *msProc) run() {
	c := ms.c
	if c.dialer {
		go func() {
			c.serve(ms.ctx)
			ms.box.send(msServed{})
		}()
		go func() {
			open, err := ms.dialOpen()
			ms.box.send(msOpened{open: open, err: err})
		}()
	} else {
		ms.setUp()
	}
	closed := c.qc.Context().Done()
	for closed != nil || !ms.served {
		select {
		case <-ms.box.sig:
			for _, e := range ms.box.take() {
				ms.handle(e)
			}
		case <-closed:
			closed = nil
			ms.cancel()
		}
	}
	ms.cancel()
	for _, e := range ms.box.close() {
		ms.refuse(e)
	}
	restart := false
	if code, msg, remote := remoteClose(c.qc, nil); remote {
		restart = code == dpv1.MeshCloseCode_MESH_CLOSE_CODE_RESTART
		if ms.err == nil {
			ms.err = fmt.Errorf("relay closed the session with %v: %s", code, msg)
		}
	}
	if ms.up {
		slog.Info("Closed mesh session", "relay", ms.name, "reason", context.Cause(c.qc.Context()))
	}
	ms.mbox.send(msEnded{ms: ms, up: ms.up, restart: restart, err: ms.err})
}

// setUp opens the session for the handlers and tells M.
func (ms *msProc) setUp() {
	ms.up = true
	close(ms.c.ready)
	v := ms.open.ver
	slog.Info("Opened mesh session", "relay", ms.name, "remote", ms.c.qc.RemoteAddr(), "dialer", ms.c.dialer,
		"revision", v.GetRevision(), "build", buildLabel(v.GetBuild()))
	ms.mbox.send(msUp{ms: ms})
}

func (ms *msProc) handle(e any) {
	switch e := e.(type) {
	case msOpened:
		if e.err != nil {
			ms.err = e.err
			return
		}
		ms.open = e.open
		ms.setUp()
	case msServed:
		ms.served = true
	case msEnd:
		ms.c.close(e.code, e.msg)
	case msIncoming:
		if !ms.up || !ms.mbox.send(mIncoming{ms: ms, msIncoming: e}) {
			e.done <- rpc.Errorf(rpc.Unavailable, "mesh session ended")
		}
	case msTrunkKeys:
		if !ms.up || !ms.mbox.send(mTrunkApply{ms: ms, msTrunkKeys: e}) {
			e.res <- callResult{err: rpc.Errorf(rpc.Unavailable, "mesh session ended")}
		}
	}
}

// refuse answers a call that came after the end of the session.
func (ms *msProc) refuse(e any) {
	switch e := e.(type) {
	case msIncoming:
		e.done <- rpc.Errorf(rpc.Unavailable, "mesh session ended")
	case msTrunkKeys:
		e.res <- callResult{err: rpc.Errorf(rpc.Unavailable, "mesh session ended")}
	}
}

// dialOpen checks the certificate of the dialed member and calls Open. A failure closes the
// connection.
func (ms *msProc) dialOpen() (msOpen, error) {
	ctx, cancel := context.WithTimeout(ms.ctx, meshOpenTimeout)
	defer cancel()
	r, c := ms.r, ms.c
	dialed := addrPort(c.qc.RemoteAddr())
	if err := r.mesh.cfg.Verify(c.qc.ConnectionState().TLS.PeerCertificates, ms.name, dialed); err != nil {
		c.close(dpv1.MeshCloseCode_MESH_CLOSE_CODE_NOT_MEMBER, "relay certificate rejected")
		return msOpen{}, fmt.Errorf("relay certificate rejected: %w", err)
	}
	res, err := c.client.Open(ctx, r.openRequest())
	if err != nil {
		if code, reason, ok := remoteClose(c.qc, err); ok {
			err = fmt.Errorf("relay closed the session with %v: %s", code, reason)
		}
		c.close(dpv1.MeshCloseCode_MESH_CLOSE_CODE_UNSPECIFIED, "")
		return msOpen{}, fmt.Errorf("open: %w", err)
	}
	if got := res.GetName(); got != ms.name {
		err := fmt.Errorf("relay %q is not the member %q that this relay dialed", got, ms.name)
		c.close(dpv1.MeshCloseCode_MESH_CLOSE_CODE_NOT_MEMBER, err.Error())
		return msOpen{}, err
	}
	if err := r.checkRevision(res.GetVersion()); err != nil {
		c.close(dpv1.MeshCloseCode_MESH_CLOSE_CODE_UPGRADE, err.Error())
		return msOpen{}, err
	}
	// An empty host is the host that this relay dialed.
	psp, err := pspSocket(res.GetPspHost(), res.GetPspPort(), dialed.Addr())
	if err != nil {
		c.close(dpv1.MeshCloseCode_MESH_CLOSE_CODE_UNSPECIFIED, err.Error())
		return msOpen{}, err
	}
	return msOpen{name: ms.name, ref: res.GetRelay(), ver: res.GetVersion(), psp: psp}, nil
}
