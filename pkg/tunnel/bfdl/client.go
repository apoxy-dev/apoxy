package bfdl

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"time"

	apoxynet "github.com/apoxy-dev/apoxy/pkg/tunnel/net"
)

// BFDServerAddr is the well-known server-side BFD address (proxySourceAddr).
var BFDServerAddr = netip.MustParseAddr(apoxynet.ApoxyULAAddr)

// Client drives a BFD session from the tunnel agent side.
type Client struct {
	session    *Session
	conn       net.PacketConn
	serverAddr netip.AddrPort

	// downCh is closed when the session transitions to Down from Up
	// (detect timer expired). Consumers should select on this to
	// trigger connection teardown.
	downCh chan struct{}
}

// NewClient creates a new BFD client.
func NewClient(conn net.PacketConn, serverAddr netip.AddrPort) *Client {
	localDiscr := rand.Uint32()
	for localDiscr == 0 {
		localDiscr = rand.Uint32()
	}

	c := &Client{
		conn:       conn,
		serverAddr: serverAddr,
		downCh:     make(chan struct{}),
	}

	session := NewSession(localDiscr, DefaultDetectMult, DefaultTxInterval)
	session.SetOnStateChange(func(old, new State) {
		slog.Info("BFD client session state change",
			"from", old.String(),
			"to", new.String())
		BFDSessionsActive.WithLabelValues("client", old.String()).Dec()
		BFDSessionsActive.WithLabelValues("client", new.String()).Inc()
		BFDStateTransitions.WithLabelValues("client", old.String(), new.String()).Inc()
	})
	c.session = session

	BFDSessionsActive.WithLabelValues("client", StateDown.String()).Inc()

	return c
}

// Down returns a channel that is closed when the BFD session transitions
// from Up to Down (detect timer expired). The channel is closed at most once.
func (c *Client) Down() <-chan struct{} {
	return c.downCh
}

// Run drives the BFD session: sends periodic control packets and processes
// responses. Blocks until ctx is canceled.
func (c *Client) Run(ctx context.Context) error {
	defer func() {
		BFDSessionsActive.WithLabelValues("client", c.session.State().String()).Dec()
	}()

	txTicker := time.NewTicker(DefaultTxInterval)
	defer txTicker.Stop()

	detectTicker := time.NewTicker(1 * time.Second)
	defer detectTicker.Stop()

	// Read goroutine.
	readCh := make(chan *Packet, 4)
	go func() {
		buf := make([]byte, 128)
		for {
			n, _, err := c.conn.ReadFrom(buf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				slog.Debug("BFD client read error", "error", err)
				BFDPacketErrors.WithLabelValues("client", "rx").Inc()
				continue
			}
			pkt, err := Unmarshal(buf[:n])
			if err != nil {
				slog.Debug("BFD client unmarshal error", "error", err)
				BFDPacketErrors.WithLabelValues("client", "rx").Inc()
				continue
			}
			BFDPacketsRx.WithLabelValues("client").Inc()
			select {
			case readCh <- pkt:
			default:
			}
		}
	}()

	// Send initial packet immediately.
	c.sendTx()

	dst := net.UDPAddrFromAddrPort(c.serverAddr)
	for {
		select {
		case <-ctx.Done():
			return nil
		case pkt := <-readCh:
			resp := c.session.ProcessRx(pkt)
			if resp != nil {
				out := Marshal(resp)
				if _, err := c.conn.WriteTo(out, dst); err != nil {
					slog.Debug("BFD client write error", "error", err)
					BFDPacketErrors.WithLabelValues("client", "tx").Inc()
				} else {
					BFDPacketsTx.WithLabelValues("client").Inc()
				}
			}
		case <-txTicker.C:
			c.sendTx()
		case <-detectTicker.C:
			if c.session.Expired() && c.session.State() == StateUp {
				slog.Warn("BFD client session expired, transitioning to Down")
				BFDDetectTimeouts.WithLabelValues("client").Inc()
				c.session.mu.Lock()
				old := c.session.localState
				c.session.localState = StateDown
				c.session.remoteDiscr = 0
				if c.session.onStateChange != nil {
					c.session.onStateChange(old, StateDown)
				}
				c.session.mu.Unlock()

				// Signal consumers that BFD failed.
				select {
				case <-c.downCh:
					// Already closed.
				default:
					close(c.downCh)
				}
			}
		}
	}
}

func (c *Client) sendTx() {
	pkt := c.session.BuildTx()
	out := Marshal(pkt)
	dst := net.UDPAddrFromAddrPort(c.serverAddr)
	if _, err := c.conn.WriteTo(out, dst); err != nil {
		slog.Debug("BFD client write error", "error", err)
		BFDPacketErrors.WithLabelValues("client", "tx").Inc()
	} else {
		BFDPacketsTx.WithLabelValues("client").Inc()
	}
}

// State returns the current BFD session state.
func (c *Client) State() State {
	return c.session.State()
}

// LastAlive returns when the last valid BFD packet was received from the server.
func (c *Client) LastAlive() time.Time {
	return c.session.LastRx()
}
