package batchpc_test

import (
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/batchpc"
)

func TestBatchPC(t *testing.T) {
	t.Run("unsupported network", func(t *testing.T) {
		pc := makeUDPListener(t, "udp4", "127.0.0.1:0")
		t.Cleanup(func() { require.NoError(t, pc.Close()) })
		_, err := batchpc.New("tcp", pc)
		require.Error(t, err)
		require.ErrorContains(t, err, "unsupported network")
	})

	t.Run("non-udpconn not supported", func(t *testing.T) {
		// Use a dummy PacketConn to confirm we reject non-*net.UDPConn.
		pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, pc.Close()) })
		// Wrap in a custom type that is NOT *net.UDPConn
		type justPC struct{ net.PacketConn }
		_, err = batchpc.New("udp4", justPC{PacketConn: pc})
		require.Error(t, err)
		require.ErrorContains(t, err, "only *net.UDPConn is supported")
	})

	t.Run("zero-length Read/Write", func(t *testing.T) {
		pc := makeUDPListener(t, "udp4", "127.0.0.1:0")
		t.Cleanup(func() { require.NoError(t, pc.Close()) })
		bc := mustBatch(t, "udp4", pc)

		n, err := bc.ReadBatch(nil, 0)
		require.NoError(t, err)
		require.Equal(t, 0, n)

		n, err = bc.WriteBatch(nil, 0)
		require.NoError(t, err)
		require.Equal(t, 0, n)
	})

	type scenario struct {
		name      string
		netListen string // actual socket family
		addr      string
		hintSrv   string
		hintCli   string
		counts    []int // how many packets per send burst
	}
	tests := []scenario{
		{
			name:      "ipv4-direct-explicit",
			netListen: "udp4", addr: "127.0.0.1:0",
			hintSrv: "udp4", hintCli: "udp4",
			counts: []int{4},
		},
		{
			name:      "ipv6-direct-explicit",
			netListen: "udp6", addr: "[::1]:0",
			hintSrv: "udp6", hintCli: "udp6",
			counts: []int{3},
		},
		{
			name:      "ipv4-infer-empty-and-udp",
			netListen: "udp4", addr: "127.0.0.1:0",
			hintSrv: "", hintCli: "udp", // exercises resolveNetwork inference
			counts: []int{4},
		},
		{
			name:      "ipv6-infer-empty-and-udp",
			netListen: "udp6", addr: "[::1]:0",
			hintSrv: "", hintCli: "udp",
			counts: []int{4},
		},
		{
			name:      "ipv4-pool-grows-beyond-MaxBatchSize",
			netListen: "udp4", addr: "127.0.0.1:0",
			hintSrv: "udp4", hintCli: "udp4",
			// send once with MaxBatchSize+1 to cover pool growth path
			counts: []int{batchpc.MaxBatchSize + 1},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// Server
			srvUDP := makeUDPListener(t, tc.netListen, tc.addr)
			t.Cleanup(func() { require.NoError(t, srvUDP.Close()) })
			srv, err := batchpc.New(tc.hintSrv, srvUDP)
			require.NoError(t, err)

			// Client
			cliUDP := makeUDPListener(t, tc.netListen, tc.addr)
			t.Cleanup(func() { require.NoError(t, cliUDP.Close()) })
			cli, err := batchpc.New(tc.hintCli, cliUDP)
			require.NoError(t, err)

			total := 0
			for _, c := range tc.counts {
				total += c
			}
			done := startEcho(t, srv, total)

			// Send bursts to server and read replies
			serverAddr := srv.LocalAddr()

			// Writable window
			for _, burst := range tc.counts {
				out := make([]batchpc.Message, burst)
				for i := 0; i < burst; i++ {
					out[i] = batchpc.Message{
						Buf:  []byte(tc.name + "/" + strconv.Itoa(i)),
						Addr: serverAddr,
					}
				}
				_ = cli.SetWriteDeadline(time.Now().Add(3 * time.Second))
				wn, err := cli.WriteBatch(out, 0)
				require.NoError(t, err)
				require.Equal(t, burst, wn)
			}

			// Read back all replies (order-preserving within batch)
			in := make([]batchpc.Message, total)
			for i := range in {
				in[i].Buf = make([]byte, 1500)
			}
			got := 0
			dead := time.Now().Add(5 * time.Second)
			for got < total && time.Now().Before(dead) {
				_ = cli.SetReadDeadline(time.Now().Add(3 * time.Second))
				rn, err := cli.ReadBatch(in[got:], 0)
				require.NoError(t, err)
				require.Greater(t, rn, 0)
				got += rn
			}
			require.Equal(t, total, got, "didn't receive all echoes")

			// Basic validation of content trim and Addr non-nil.
			for i := 0; i < got; i++ {
				require.NotEmpty(t, in[i].Buf)
				require.NotNil(t, in[i].Addr)
			}

			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("echo server did not finish")
			}
		})
	}
}

func makeUDPListener(t *testing.T, network, addr string) *net.UDPConn {
	t.Helper()
	pc, err := net.ListenPacket(network, addr)
	if err != nil {
		t.Skipf("skip %s: %v", network, err)
	}
	uc, ok := pc.(*net.UDPConn)
	require.True(t, ok, "expected *net.UDPConn, got %T", pc)
	return uc
}

// startEcho spins an echo loop that reads batches and writes them back.
// It stops after echoing 'want' packets total.
func startEcho(t *testing.T, bc batchpc.BatchPacketConn, want int) chan struct{} {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		left := want
		bufs := make([]batchpc.Message, 0, 64)
		for left > 0 {
			// resize receive window to what's left (bounded)
			nwin := left
			if nwin > 32 {
				nwin = 32
			}
			if cap(bufs) < nwin {
				bufs = make([]batchpc.Message, 0, nwin)
			}
			bufs = bufs[:nwin]
			for i := range bufs {
				bufs[i].Buf = make([]byte, 1500)
				bufs[i].Addr = nil
			}
			_ = bc.SetReadDeadline(time.Now().Add(3 * time.Second))
			rn, err := bc.ReadBatch(bufs, 0)
			if errors.Is(err, net.ErrClosed) {
				return
			}
			require.NoError(t, err)
			require.Greater(t, rn, 0)

			out := make([]batchpc.Message, rn)
			for i := 0; i < rn; i++ {
				out[i] = batchpc.Message{
					Buf:  append([]byte(nil), bufs[i].Buf...), // exact copy/length
					Addr: bufs[i].Addr,
				}
			}
			_ = bc.SetWriteDeadline(time.Now().Add(3 * time.Second))
			wn, err := bc.WriteBatch(out, 0)
			require.NoError(t, err)
			require.Equal(t, rn, wn)

			left -= rn
		}
	}()
	return done
}

func mustBatch(t *testing.T, network string, pc net.PacketConn) batchpc.BatchPacketConn {
	t.Helper()
	bc, err := batchpc.New(network, pc)
	require.NoError(t, err)
	return bc
}
