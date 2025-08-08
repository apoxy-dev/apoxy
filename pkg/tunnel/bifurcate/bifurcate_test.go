package bifurcate_test

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/apoxy-dev/icx/geneve"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/bifurcate"
)

type MockPacketConn struct {
	mock.Mock
	readQueue chan readResult
	addr      net.Addr
	closed    bool
}

type readResult struct {
	data []byte
	addr net.Addr
	err  error
}

func NewMockPacketConn() *MockPacketConn {
	return &MockPacketConn{
		readQueue: make(chan readResult, 10),
		addr:      &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345},
	}
}

func (m *MockPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	result, ok := <-m.readQueue
	if !ok {
		return 0, nil, errors.New("mock read closed")
	}
	n := copy(p, result.data)
	return n, result.addr, result.err
}

func (m *MockPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	args := m.Called(p, addr)
	return args.Int(0), args.Error(1)
}

func (m *MockPacketConn) Close() error {
	m.closed = true
	close(m.readQueue)
	return nil
}

func (m *MockPacketConn) LocalAddr() net.Addr                { return m.addr }
func (m *MockPacketConn) SetDeadline(t time.Time) error      { return nil }
func (m *MockPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *MockPacketConn) SetWriteDeadline(t time.Time) error { return nil }

// --- Helpers ---

func createGenevePacket(t *testing.T) []byte {
	header := geneve.Header{
		Version:      0,
		ProtocolType: 0x6558,
		VNI:          0x123456,
		NumOptions:   0,
	}
	buf := make([]byte, 128)
	n, err := header.MarshalBinary(buf)
	require.NoError(t, err)
	return buf[:n]
}

func createNonGenevePacket() []byte {
	return []byte("this is not a geneve packet")
}

func TestBifurcate(t *testing.T) {
	t.Run("routes geneve and non-geneve packets to correct connections", func(t *testing.T) {
		mockConn := NewMockPacketConn()
		remote := &net.UDPAddr{IP: net.IPv4(10, 1, 1, 1), Port: 9999}

		// Prepare packets
		genevePkt := createGenevePacket(t)
		nonGenevePkt := createNonGenevePacket()

		mockConn.readQueue <- readResult{data: genevePkt, addr: remote}
		mockConn.readQueue <- readResult{data: nonGenevePkt, addr: remote}

		geneveConn, otherConn := bifurcate.Bifurcate(mockConn)

		// Read from geneveConn
		buf := make([]byte, 1024)
		n, addr, err := geneveConn.ReadFrom(buf)
		require.NoError(t, err)
		require.Equal(t, remote.String(), addr.String())
		require.True(t, bytes.HasPrefix(buf[:n], genevePkt))

		// Read from otherConn
		n, addr, err = otherConn.ReadFrom(buf)
		require.NoError(t, err)
		require.Equal(t, remote.String(), addr.String())
		require.Equal(t, string(buf[:n]), string(nonGenevePkt))
	})

	t.Run("closes both connections on read error", func(t *testing.T) {
		mockConn := NewMockPacketConn()
		// simulate read error by closing channel
		close(mockConn.readQueue)

		geneveConn, otherConn := bifurcate.Bifurcate(mockConn)

		// wait for goroutine to detect closure
		time.Sleep(50 * time.Millisecond)

		buf := make([]byte, 1024)

		_, _, err := geneveConn.ReadFrom(buf)
		require.ErrorIs(t, err, net.ErrClosed)

		_, _, err = otherConn.ReadFrom(buf)
		require.ErrorIs(t, err, net.ErrClosed)
	})
}
