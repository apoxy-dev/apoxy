package bifurcate_test

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/apoxy-dev/icx/geneve"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/batchpc"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/bifurcate"
)

func TestBifurcate_RoutesWithReadFrom(t *testing.T) {
	mockConn := newMockBatchPacketConn()
	remote := &net.UDPAddr{IP: net.IPv4(10, 1, 1, 1), Port: 9999}

	genevePkt := createGenevePacket(t)
	nonGenevePkt := createNonGenevePacket()

	mockConn.enqueue(genevePkt, remote)
	mockConn.enqueue(nonGenevePkt, remote)

	geneveConn, otherConn := bifurcate.Bifurcate(mockConn)

	// Read Geneve
	buf := make([]byte, 1024)
	n, addr, err := geneveConn.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, remote.String(), addr.String())
	require.True(t, bytes.Equal(buf[:n], genevePkt))

	// Read other
	n, addr, err = otherConn.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, remote.String(), addr.String())
	require.Equal(t, string(nonGenevePkt), string(buf[:n]))
}

func TestBifurcate_ReadBatch_RoutesBatchesToBoth(t *testing.T) {
	mockConn := newMockBatchPacketConn()
	remoteG := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 10001}
	remoteO := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 10002}

	genevePkt := createGenevePacket(t)
	nonGenevePkt := createNonGenevePacket()

	// Enqueue a mixed stream larger than child batch request sizes.
	for i := 0; i < 5; i++ {
		mockConn.enqueue(genevePkt, remoteG)
	}
	for i := 0; i < 3; i++ {
		mockConn.enqueue(nonGenevePkt, remoteO)
	}

	geneveConn, otherConn := bifurcate.Bifurcate(mockConn)

	// Child buffers
	makeMsgs := func(n int, sz int) []batchpc.Message {
		msgs := make([]batchpc.Message, n)
		for i := range msgs {
			msgs[i].Buf = make([]byte, sz)
		}
		return msgs
	}

	// Read a batch from both sides
	gmsgs := makeMsgs(4, 256)
	n1, err := geneveConn.ReadBatch(gmsgs, 0)
	require.NoError(t, err)
	require.Equal(t, 4, n1)
	for i := 0; i < n1; i++ {
		require.True(t, bytes.Equal(gmsgs[i].Buf, genevePkt))
		require.Equal(t, remoteG.String(), gmsgs[i].Addr.String())
	}

	omsgs := makeMsgs(2, 256)
	n2, err := otherConn.ReadBatch(omsgs, 0)
	require.NoError(t, err)
	require.Equal(t, 2, n2)
	for i := 0; i < n2; i++ {
		require.Equal(t, string(nonGenevePkt), string(omsgs[i].Buf))
		require.Equal(t, remoteO.String(), omsgs[i].Addr.String())
	}

	// Read remaining packets from both
	gmsgs2 := makeMsgs(8, 256)
	n3, err := geneveConn.ReadBatch(gmsgs2, 0)
	require.NoError(t, err)
	require.Equal(t, 1, n3) // 5 total geneve, 4 already read
	require.True(t, bytes.Equal(gmsgs2[0].Buf, genevePkt))

	omsgs2 := makeMsgs(8, 256)
	n4, err := otherConn.ReadBatch(omsgs2, 0)
	require.NoError(t, err)
	require.Equal(t, 1, n4) // 3 total non-geneve, 2 already read
	require.Equal(t, string(nonGenevePkt), string(omsgs2[0].Buf))
}

func TestBifurcate_ChildReadBatchDrainsPending(t *testing.T) {
	mockConn := newMockBatchPacketConn()
	remote := &net.UDPAddr{IP: net.IPv4(10, 2, 3, 4), Port: 4242}
	genevePkt := createGenevePacket(t)

	// Enqueue several geneve packets so the bifurcator sends a whole batch.
	for i := 0; i < 6; i++ {
		mockConn.enqueue(genevePkt, remote)
	}

	geneveConn, _ := bifurcate.Bifurcate(mockConn)

	msgs := make([]batchpc.Message, 8)
	for i := range msgs {
		msgs[i].Buf = make([]byte, 256)
	}
	n, err := geneveConn.ReadBatch(msgs, 0)
	require.NoError(t, err)
	require.Equal(t, 6, n)
	for i := 0; i < n; i++ {
		require.True(t, bytes.Equal(msgs[i].Buf, genevePkt))
	}
}

func TestBifurcate_WriteBatchForwardsToUnderlying(t *testing.T) {
	mockConn := newMockBatchPacketConn()
	geneveConn, otherConn := bifurcate.Bifurcate(mockConn)

	dst := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 1), Port: 9999}
	payloads := [][]byte{
		[]byte("a"),
		[]byte("bb"),
		[]byte("ccc"),
	}
	msgs := make([]batchpc.Message, len(payloads))
	for i := range msgs {
		msgs[i].Buf = payloads[i]
		msgs[i].Addr = dst
	}

	// Send via geneve child
	n1, err := geneveConn.WriteBatch(msgs, 0)
	require.NoError(t, err)
	require.Equal(t, len(payloads), n1)

	// Send via other child
	n2, err := otherConn.WriteBatch(msgs, 0)
	require.NoError(t, err)
	require.Equal(t, len(payloads), n2)

	// Verify underlying was called and captured content.
	mockConn.mu.Lock()
	defer mockConn.mu.Unlock()
	require.GreaterOrEqual(t, mockConn.writeBatchCalls, 2)
	require.Len(t, mockConn.lastWriteBatch, len(payloads))
	for i := range payloads {
		require.Equal(t, string(payloads[i]), string(mockConn.lastWriteBatch[i]))
		require.Equal(t, dst.String(), mockConn.lastWriteBatchTo[i].String())
	}
}

func TestBifurcate_ClosesBothOnUnderlyingClose(t *testing.T) {
	mockConn := newMockBatchPacketConn()

	geneveConn, otherConn := bifurcate.Bifurcate(mockConn)

	// close the underlying connection
	_ = mockConn.Close()

	// Give the goroutine a breath to observe the close.
	time.Sleep(50 * time.Millisecond)

	buf := make([]byte, 1024)
	_, _, err := geneveConn.ReadFrom(buf)
	require.ErrorIs(t, err, net.ErrClosed)

	_, _, err = otherConn.ReadFrom(buf)
	require.ErrorIs(t, err, net.ErrClosed)
}

func TestBifurcate_BubblesTransientErrorAndContinues(t *testing.T) {
	t.Helper()

	mockConn := newMockBatchPacketConn()
	transientErr := errors.New("temporary I/O error")

	remote := &net.UDPAddr{IP: net.IPv4(10, 9, 8, 7), Port: 31337}
	genevePkt := createGenevePacket(t)

	// First queued result is a transient error (channel stays open).
	mockConn.readQueue <- readResult{
		err: transientErr,
	}
	// Second queued result is a valid Geneve packet.
	mockConn.enqueue(genevePkt, remote)

	geneveConn, _ := bifurcate.Bifurcate(mockConn)

	// Give the bifurcator goroutine a moment to observe both queued results:
	// 1) record transientErr via setErr(...)
	// 2) enqueue the good packet batch onto geneveConn.ch
	time.Sleep(50 * time.Millisecond)

	buf := make([]byte, 1024)

	// First read should surface the transient error that was bubbled up.
	_, _, err := geneveConn.ReadFrom(buf)
	require.ErrorIs(t, err, transientErr)

	// Second read should now succeed and return the real packet.
	n, addr, err := geneveConn.ReadFrom(buf)
	require.NoError(t, err)
	require.Equal(t, remote.String(), addr.String())
	require.True(t, bytes.Equal(buf[:n], genevePkt), "expected geneve packet after transient error")
}

func createGenevePacket(t *testing.T) []byte {
	h := geneve.Header{
		Version:      0,
		ProtocolType: uint16(header.IPv4ProtocolNumber),
		VNI:          0x123456,
		NumOptions:   2,
		Options: [2]geneve.Option{
			{Class: geneve.ClassExperimental, Type: 1},
			{Class: geneve.ClassExperimental, Type: 2},
		},
	}
	buf := make([]byte, 128)
	n, err := h.MarshalBinary(buf)
	require.NoError(t, err)
	return buf[:n]
}

func createNonGenevePacket() []byte {
	return []byte("this is not a geneve packet")
}

type readResult struct {
	data []byte
	addr net.Addr
	err  error
}

type mockBatchPacketConn struct {
	readQueue chan readResult
	addr      net.Addr

	mu               sync.Mutex
	closed           bool
	writeToCalls     int
	lastWriteToBuf   []byte
	lastWriteToAddr  net.Addr
	writeBatchCalls  int
	lastWriteBatch   [][]byte
	lastWriteBatchTo []net.Addr
}

func newMockBatchPacketConn() *mockBatchPacketConn {
	return &mockBatchPacketConn{
		readQueue: make(chan readResult, 64),
		addr:      &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345},
	}
}

func (pc *mockBatchPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	// Convenience shim using ReadBatch semantics
	msgs := []batchpc.Message{{Buf: p}}
	n, err := pc.ReadBatch(msgs, 0)
	if n == 0 {
		return 0, nil, err
	}
	return len(msgs[0].Buf), msgs[0].Addr, err
}

func (pc *mockBatchPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	pc.mu.Lock()
	pc.writeToCalls++
	pc.lastWriteToBuf = append(pc.lastWriteToBuf[:0], p...)
	pc.lastWriteToAddr = addr
	pc.mu.Unlock()
	return len(p), nil
}

func (pc *mockBatchPacketConn) Close() error {
	pc.mu.Lock()
	if !pc.closed {
		pc.closed = true
		close(pc.readQueue)
	}
	pc.mu.Unlock()
	return nil
}

func (pc *mockBatchPacketConn) LocalAddr() net.Addr {
	return pc.addr
}

func (pc *mockBatchPacketConn) SetDeadline(t time.Time) error {
	return nil
}

func (pc *mockBatchPacketConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (pc *mockBatchPacketConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func (pc *mockBatchPacketConn) ReadBatch(msgs []batchpc.Message, flags int) (int, error) {
	if len(msgs) == 0 {
		return 0, nil
	}

	// First result: block
	result, ok := <-pc.readQueue
	if !ok {
		// underlying permanently closed
		return 0, net.ErrClosed
	}
	if result.err != nil {
		return 0, result.err
	}

	n0 := copy(msgs[0].Buf, result.data)
	msgs[0].Buf = msgs[0].Buf[:n0]
	msgs[0].Addr = result.addr
	n := 1

	// Drain non-blocking
	for n < len(msgs) {
		select {
		case rr, ok := <-pc.readQueue:
			if !ok {
				return n, net.ErrClosed
			}
			if rr.err != nil {
				return n, rr.err
			}
			cn := copy(msgs[n].Buf, rr.data)
			msgs[n].Buf = msgs[n].Buf[:cn]
			msgs[n].Addr = rr.addr
			n++
		default:
			return n, nil
		}
	}

	return n, nil
}

func (pc *mockBatchPacketConn) WriteBatch(msgs []batchpc.Message, flags int) (int, error) {
	pc.mu.Lock()
	pc.writeBatchCalls++
	pc.lastWriteBatch = pc.lastWriteBatch[:0]
	pc.lastWriteBatchTo = pc.lastWriteBatchTo[:0]
	for _, ms := range msgs {
		cp := append([]byte(nil), ms.Buf...)
		pc.lastWriteBatch = append(pc.lastWriteBatch, cp)
		pc.lastWriteBatchTo = append(pc.lastWriteBatchTo, ms.Addr)
	}
	pc.mu.Unlock()
	return len(msgs), nil
}

func (pc *mockBatchPacketConn) enqueue(data []byte, addr net.Addr) {
	pc.readQueue <- readResult{data: append([]byte(nil), data...), addr: addr, err: nil}
}
