package conntrackpc_test

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/conntrackpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenSendReceive(t *testing.T) {
	under, local := makeUDP(t)
	ct := conntrackpc.New(under, conntrackpc.Options{
		AutoCreate: false,
		TTL:        time.Minute,
		MaxFlows:   32,
		RxBufSize:  8,
	})
	t.Cleanup(func() { _ = ct.Close() })

	peerPC, peerAddr := makeUDP(t)

	// Open a virtual connection bound to peerAddr and exchange packets.
	v, err := ct.Open(peerAddr)
	require.NoError(t, err)

	// Send from peer -> ct -> v
	payload1 := []byte("hello from peer")
	sendTo(t, peerPC, local, payload1)

	buf := make([]byte, 1500)
	// Virtual read should deliver exactly what peer sent, and report peer's addr.
	require.NoError(t, v.SetReadDeadline(time.Now().Add(2*time.Second)))
	n, addr, err := v.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, peerAddr.String(), addr.String())
	assert.Equal(t, payload1, buf[:n])

	// Send from v -> peer
	payload2 := []byte("hi back from vconn")
	nw, err := v.WriteTo(payload2, nil) // nil addr => use bound remote
	require.NoError(t, err)
	assert.Equal(t, len(payload2), nw)

	got, from := recvFrom(t, peerPC, 2*time.Second)
	assert.Equal(t, local.String(), from.String())
	assert.Equal(t, payload2, got)
}

func TestAutoCreateOnInbound(t *testing.T) {
	under, local := makeUDP(t)
	ct := conntrackpc.New(under, conntrackpc.Options{
		AutoCreate: true,
		TTL:        time.Minute,
		MaxFlows:   32,
		RxBufSize:  8,
	})
	t.Cleanup(func() { _ = ct.Close() })

	peerPC, peerAddr := makeUDP(t)

	// Deliver a packet before calling Open: should auto-create the flow and queue it.
	payload := []byte("first contact")
	sendTo(t, peerPC, local, payload)

	// Now Open should return the existing virtual conn, with the first packet waiting.
	v, err := ct.Open(peerAddr)
	require.NoError(t, err)

	buf := make([]byte, 1500)
	require.NoError(t, v.SetReadDeadline(time.Now().Add(2*time.Second)))
	n, addr, err := v.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, peerAddr.String(), addr.String())
	assert.Equal(t, payload, buf[:n])
}

func TestReadDeadlineTimeout(t *testing.T) {
	under, _ := makeUDP(t)
	ct := conntrackpc.New(under, conntrackpc.Options{
		AutoCreate: false,
		TTL:        time.Minute,
		MaxFlows:   32,
		RxBufSize:  8,
	})
	t.Cleanup(func() { _ = ct.Close() })

	_, peerAddr := makeUDP(t)
	v, err := ct.Open(peerAddr)
	require.NoError(t, err)

	// No packets inbound; a near-term read deadline should time out.
	deadline := time.Now().Add(50 * time.Millisecond)
	require.NoError(t, v.SetReadDeadline(deadline))

	buf := make([]byte, 1500)
	_, _, err = v.ReadFrom(buf)
	var nerr net.Error
	require.ErrorAs(t, err, &nerr)
	assert.True(t, nerr.Timeout(), "expected timeout error")
}

func TestTTLExpiryEvictsAndClosesFlow(t *testing.T) {
	under, _ := makeUDP(t)
	ct := conntrackpc.New(under, conntrackpc.Options{
		AutoCreate: false,
		TTL:        80 * time.Millisecond,
		MaxFlows:   32,
		RxBufSize:  8,
	})
	t.Cleanup(func() { _ = ct.Close() })

	_, peerAddr := makeUDP(t)
	v, err := ct.Open(peerAddr)
	require.NoError(t, err)

	// Wait past TTL plus a little. The LRU eviction happens when TTL expires,
	// driven by cache access/ops; NewLRU with expirable TTL evicts lazily on Ops.
	// We trigger an op by opening another key to ensure eviction occurs.
	time.Sleep(120 * time.Millisecond)

	// Touch the cache to provoke TTL cleanup; use a different dummy remote.
	_, other := makeUDP(t)
	_, _ = ct.Open(other) // triggers internal add + housekeeping

	// The old vconn should now be closed; a read should return net.ErrClosed quickly.
	require.NoError(t, v.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
	_, _, err = v.ReadFrom(make([]byte, 1))
	require.Error(t, err)
	assert.True(t, errors.Is(err, net.ErrClosed), "expected net.ErrClosed after TTL eviction")
}

func TestMaxFlowsEvictsOldestAndCloses(t *testing.T) {
	under, _ := makeUDP(t)
	ct := conntrackpc.New(under, conntrackpc.Options{
		AutoCreate: false,
		TTL:        time.Minute,
		MaxFlows:   1, // only one flow allowed
		RxBufSize:  8,
	})
	t.Cleanup(func() { _ = ct.Close() })

	_, a := makeUDP(t)
	va, err := ct.Open(a)
	require.NoError(t, err)

	// Open a second flow; LRU should evict 'a' and close it.
	_, b := makeUDP(t)
	vb, err := ct.Open(b)
	require.NoError(t, err)
	require.NotNil(t, vb)

	// Reading from the evicted first flow should yield net.ErrClosed.
	require.NoError(t, va.SetReadDeadline(time.Now().Add(50*time.Millisecond)))
	_, _, err = va.ReadFrom(make([]byte, 1))
	require.Error(t, err)
	assert.True(t, errors.Is(err, net.ErrClosed))
}

func TestAllowAddrOverrideOnWriteRekeysFlow(t *testing.T) {
	under, local := makeUDP(t)
	ct := conntrackpc.New(under, conntrackpc.Options{
		AutoCreate:               true,
		TTL:                      time.Minute,
		MaxFlows:                 32,
		RxBufSize:                8,
		AllowAddrOverrideOnWrite: true,
	})
	t.Cleanup(func() { _ = ct.Close() })

	// Two peers
	peer1PC, peer1 := makeUDP(t)
	peer2PC, peer2 := makeUDP(t)

	// Establish flow with peer1
	v, err := ct.Open(peer1)
	require.NoError(t, err)

	// Write to peer2 using override; this should re-key the virtual flow to peer2.
	msg := []byte("rekey to peer2")
	nw, err := v.WriteTo(msg, peer2)
	require.NoError(t, err)
	assert.Equal(t, len(msg), nw)

	// Peer2 should receive it.
	got, from := recvFrom(t, peer2PC, 2*time.Second)
	assert.Equal(t, local.String(), from.String())
	assert.Equal(t, msg, got)

	// Now send from peer2 back to ct; v should receive it (flow has re-keyed).
	reply := []byte("ack from peer2")
	sendTo(t, peer2PC, local, reply)

	buf := make([]byte, 1500)
	require.NoError(t, v.SetReadDeadline(time.Now().Add(2*time.Second)))
	n, addr, err := v.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, peer2.String(), addr.String())
	assert.Equal(t, reply, buf[:n])

	// And a packet from peer1 should auto-create a *new* flow (since v moved).
	sendTo(t, peer1PC, local, []byte("peer1 still here"))
	v1, err := ct.Open(peer1) // should be a different handle than v
	require.NoError(t, err)
	require.NoError(t, v1.SetReadDeadline(time.Now().Add(2*time.Second)))
	n, _, err = v1.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, []byte("peer1 still here"), buf[:n])
}

func TestClosePropagatesToFlows(t *testing.T) {
	under, _ := makeUDP(t)
	ct := conntrackpc.New(under, conntrackpc.Options{
		AutoCreate: true,
		TTL:        time.Minute,
		MaxFlows:   32,
		RxBufSize:  8,
	})
	_, peerAddr := makeUDP(t)

	v, err := ct.Open(peerAddr)
	require.NoError(t, err)

	// Close conntrack; read on v should promptly return net.ErrClosed.
	require.NoError(t, ct.Close())

	require.NoError(t, v.SetReadDeadline(time.Now().Add(100*time.Millisecond)))
	_, _, err = v.ReadFrom(make([]byte, 1))
	require.Error(t, err)
	assert.True(t, errors.Is(err, net.ErrClosed))

	// Writes from peer should now fail at the underlying since it's closed.
	err = v.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	require.NoError(t, err)
	_, err = v.WriteTo([]byte("x"), ct.LocalAddr())
	assert.Error(t, err)
}

// makeUDP binds a UDP socket on loopback and returns it plus its *net.UDPAddr.
func makeUDP(t *testing.T) (net.PacketConn, *net.UDPAddr) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = pc.Close() })

	ua, ok := pc.LocalAddr().(*net.UDPAddr)
	require.True(t, ok)
	return pc, ua
}

// recvFrom reads one datagram with a short deadline.
func recvFrom(t *testing.T, pc net.PacketConn, d time.Duration) ([]byte, net.Addr) {
	t.Helper()
	require.NoError(t, pc.SetReadDeadline(time.Now().Add(d)))
	buf := make([]byte, 64*1024)
	n, from, err := pc.ReadFrom(buf)
	require.NoError(t, err)
	return append([]byte(nil), buf[:n]...), from
}

// sendTo writes one datagram with a short deadline.
func sendTo(t *testing.T, pc net.PacketConn, to net.Addr, payload []byte) {
	t.Helper()
	require.NoError(t, pc.SetWriteDeadline(time.Now().Add(2*time.Second)))
	_, err := pc.WriteTo(payload, to)
	require.NoError(t, err)
}
