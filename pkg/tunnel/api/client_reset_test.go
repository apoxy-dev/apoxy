package api

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/cryptoutils"
)

// TestClientRelayRestart kills a relay right after a ping and starts it again
// on the same address with the same reset key. It logs the time from the kill
// to the close of the control connection.
func TestClientRelayRestart(t *testing.T) {
	cases := []struct {
		name string
		// loops starts the ping loop with Connect. Else one ping opens the
		// control connection and only QUIC keepalives follow.
		loops     bool
		down      time.Duration
		wantReset bool
	}{
		{name: "keepalive only, restart at once"},
		{name: "ping loop, restart at once", loops: true, wantReset: true},
		{name: "ping loop, restart after 7s", loops: true, down: 7 * time.Second, wantReset: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rl := startResetRelay(t)

			pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			require.NoError(t, err)
			t.Cleanup(func() { _ = pc.Close() })
			c, err := NewClient(ClientOptions{
				BaseURL:    "https://" + rl.addr.String(),
				Agent:      "agent-a",
				TunnelName: "default",
				Token:      "token",
				TLSConfig:  &tls.Config{InsecureSkipVerify: true},
				PacketConn: pc,
			})
			require.NoError(t, err)
			t.Cleanup(func() { _ = c.Close() })
			// MTU probes are larger than 42 bytes and stop after a few probes.
			// Turn them off to get a connection that has done its probes.
			c.h3.QUICConfig.DisablePathMTUDiscovery = true
			conns := make(chan quic.EarlyConnection, 4)
			dial := c.h3.Dial
			c.h3.Dial = func(ctx context.Context, addr string, tlsConf *tls.Config, quicConf *quic.Config) (quic.EarlyConnection, error) {
				qc, err := dial(ctx, addr, tlsConf, quicConf)
				if err == nil {
					conns <- qc
				}
				return qc, err
			}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if tc.loops {
				_, err = c.Connect(ctx)
			} else {
				err = c.ping(ctx)
			}
			require.NoError(t, err)
			select {
			case <-rl.pinged:
			case <-time.After(10 * time.Second):
				t.Fatal("the relay got no ping")
			}
			// Let the answer to the ping reach the client.
			time.Sleep(100 * time.Millisecond)

			killed := time.Now()
			rl.crash()
			time.Sleep(tc.down)
			rl.start()

			select {
			case <-c.Lost():
			case <-time.After(30 * time.Second):
				t.Fatal("the client did not see the loss of the relay")
			}
			t.Logf("Kill to close: %.1fs", time.Since(killed).Seconds())

			cause := context.Cause((<-conns).Context())
			if tc.wantReset {
				var reset *quic.StatelessResetError
				require.ErrorAs(t, cause, &reset)
			} else {
				var idle *quic.IdleTimeoutError
				require.ErrorAs(t, cause, &idle)
			}
		})
	}
}

// resetRelay is a stand-in relay with a stable stateless reset key.
type resetRelay struct {
	t       *testing.T
	addr    *net.UDPAddr
	key     quic.StatelessResetKey
	tlsConf *tls.Config
	pinged  chan struct{}

	pc  *dropConn
	tr  *quic.Transport
	srv *http3.Server
}

// dropConn drops all writes after crash, so the old relay sends nothing.
type dropConn struct {
	net.PacketConn
	dead atomic.Bool
}

func (c *dropConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.dead.Load() {
		return len(p), nil
	}
	return c.PacketConn.WriteTo(p, addr)
}

func startResetRelay(t *testing.T) *resetRelay {
	t.Helper()
	_, cert, err := cryptoutils.GenerateSelfSignedTLSCert("localhost")
	require.NoError(t, err)
	rl := &resetRelay{
		t:       t,
		addr:    &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)},
		tlsConf: http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
		pinged:  make(chan struct{}, 1),
	}
	_, _ = rand.Read(rl.key[:])
	rl.start()
	t.Cleanup(rl.crash)
	return rl
}

// start serves on rl.addr. The first call picks the port.
func (rl *resetRelay) start() {
	conn, err := net.ListenUDP("udp", rl.addr)
	require.NoError(rl.t, err)
	rl.addr = conn.LocalAddr().(*net.UDPAddr)
	rl.pc = &dropConn{PacketConn: conn}
	rl.tr = &quic.Transport{Conn: rl.pc, StatelessResetKey: &rl.key}
	ln, err := rl.tr.ListenEarly(rl.tlsConf, nil)
	require.NoError(rl.t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /ping", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		select {
		case rl.pinged <- struct{}{}:
		default:
		}
	})
	mux.HandleFunc("POST /v1/tunnel/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(ConnectResponse{ID: "conn-1", VNI: 42, MTU: 1392})
	})
	rl.srv = &http3.Server{Handler: mux}
	go func() { _ = rl.srv.ServeListener(ln) }()
}

// crash stops the relay and sends nothing to the clients.
func (rl *resetRelay) crash() {
	rl.pc.dead.Store(true)
	_ = rl.srv.Close()
	_ = rl.tr.Close()
	_ = rl.pc.Close()
}
