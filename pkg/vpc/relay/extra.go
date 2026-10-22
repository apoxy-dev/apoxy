// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"

	"github.com/apoxy-dev/apoxy/pkg/vpc/relay/dp"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dpv1 "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// extraEnd ends an extra connection with msg.
type extraEnd struct{ msg string }

// extraProc is the process extra of A: one extra QUIC connection of the agent. It carries only
// data frames, which go to the port of A.
type extraProc struct {
	box   *mailbox
	abox  *mailbox
	l     *link
	st    sessionStream
	index uint32
}

// startExtra starts the extra connection l of index for the port of A.
func startExtra(r *Router, abox *mailbox, l *link, st sessionStream, port uint64, index uint32) *extraProc {
	x := &extraProc{box: newMailbox(0), abox: abox, l: l, st: st, index: index}
	go x.run(r, port)
	return x
}

func (x *extraProc) run(r *Router, port uint64) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	msg := "extra connection ended"
	err := x.st.Send(&dpv1.SessionResponse{Msg: &dpv1.SessionResponse_Welcome{Welcome: &dpv1.Welcome{
		ReflexiveAddress: x.l.remote().String(),
		Version:          r.ver,
	}}})
	if err == nil {
		done := make(chan struct{}, 2)
		go func() {
			if _, err := x.st.Recv(); err == nil {
				x.l.close(dpv1.RelayCloseCode_RELAY_CLOSE_CODE_UNSPECIFIED, rpc.Errorf(rpc.InvalidArgument, "unexpected message on an extra connection").Error())
			}
			done <- struct{}{}
		}()
		go func() {
			_ = dp.ReadFrames(ctx, r.cfg.Target, x.l.qc, port, accessSession)
			done <- struct{}{}
		}()
	wait:
		for {
			select {
			case <-done:
				break wait
			case <-x.box.sig:
				for _, e := range x.box.take() {
					if e, ok := e.(extraEnd); ok {
						msg = e.msg
						break wait
					}
				}
			}
		}
	}
	x.l.close(dpv1.RelayCloseCode_RELAY_CLOSE_CODE_UNSPECIFIED, msg)
	x.box.close()
	x.abox.send(extraEnded{index: x.index, x: x})
	x.l.streamEnd()
}
