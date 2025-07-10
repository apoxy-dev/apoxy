package connection_test

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/connection"
)

type MockConnection struct {
	mock.Mock
	closed bool
}

func (m *MockConnection) ReadPacket(p []byte) (int, error) {
	if m.closed {
		return 0, net.ErrClosed
	}

	args := m.Called(p)
	n := args.Int(0)
	copy(p, args.Get(1).([]byte))
	return n, args.Error(2)
}

func (m *MockConnection) WritePacket(p []byte) ([]byte, error) {
	args := m.Called(p)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockConnection) Close() error {
	m.closed = true
	return m.Called().Error(0)
}

func TestMuxedConnection(t *testing.T) {
	t.Run("Add and Remove Connection", func(t *testing.T) {
		mux := connection.NewDstMuxedConn()
		mockConn := new(MockConnection)
		mockConn.On("ReadPacket", mock.Anything).Return(0, []byte{}, nil).Maybe()
		mockConn.On("Close").Return(nil).Once()

		prefix := netip.MustParsePrefix("2001:db8::/96")
		mux.Add(prefix, mockConn)
		err := mux.Del(prefix)
		assert.NoError(t, err)

		// Try removing again should fail
		err = mux.Del(prefix)
		assert.Error(t, err)
	})

	t.Run("Remove Connection - Invalid Prefix", func(t *testing.T) {
		mux := connection.NewDstMuxedConn()
		prefix := netip.MustParsePrefix("192.0.2.0/24")
		err := mux.Del(prefix)
		assert.Error(t, err)
	})

	t.Run("WritePacket - Success", func(t *testing.T) {
		mux := connection.NewDstMuxedConn()
		mockConn := new(MockConnection)
		mockConn.On("ReadPacket", mock.Anything).Return(0, []byte{}, nil).Maybe()

		prefix := netip.MustParsePrefix("2001:db8::/96")
		mux.Add(prefix, mockConn)

		pkt := make([]byte, 40)
		pkt[0] = 0x60 // IPv6
		copy(pkt[24:40], netip.MustParseAddr("2001:db8::1").AsSlice())

		mockConn.On("WritePacket", pkt).Return([]byte("ok"), nil).Once()

		resp, err := mux.WritePacket(pkt)
		assert.NoError(t, err)
		assert.Equal(t, []byte("ok"), resp)
		mockConn.AssertExpectations(t)
	})

	t.Run("WritePacket - No Connection Found", func(t *testing.T) {
		mux := connection.NewDstMuxedConn()

		pkt := make([]byte, 40)
		pkt[0] = 0x60
		copy(pkt[24:40], netip.MustParseAddr("2001:db8::1").AsSlice())

		resp, err := mux.WritePacket(pkt)
		assert.Nil(t, resp)
		assert.ErrorContains(t, err, "no matching tunnel")
	})

	t.Run("ReadPacket - Success", func(t *testing.T) {
		mux := connection.NewDstMuxedConn()
		mockConn := new(MockConnection)

		expected := []byte("hello")
		mockConn.On("ReadPacket", mock.Anything).Return(len(expected), expected, nil)

		prefix := netip.MustParsePrefix("2001:db8::/96")
		mux.Add(prefix, mockConn)

		time.Sleep(10 * time.Millisecond) // let goroutine read once

		buf := make([]byte, 1500)
		n, err := mux.ReadPacket(buf)
		assert.NoError(t, err)
		assert.Equal(t, len(expected), n)
		assert.Equal(t, expected, buf[:n])
		mockConn.AssertExpectations(t)
	})

	t.Run("ReadPacket - Closed Channel", func(t *testing.T) {
		mux := connection.NewDstMuxedConn()
		_ = mux.Close()

		buf := make([]byte, 1500)
		_, err := mux.ReadPacket(buf)

		assert.ErrorIs(t, err, net.ErrClosed)
	})

	t.Run("Close - All Connections", func(t *testing.T) {
		mux := connection.NewDstMuxedConn()
		mockConn := new(MockConnection)
		mockConn.On("ReadPacket", mock.Anything).Return(0, []byte{}, nil).Maybe()
		mockConn.On("Close").Return(nil).Once()

		prefix := netip.MustParsePrefix("2001:db8::/96")
		mux.Add(prefix, mockConn)

		err := mux.Close()
		assert.NoError(t, err)
		mockConn.AssertExpectations(t)
	})
}

func TestSrcMuxedConnection(t *testing.T) {
	t.Run("WritePacket - Success with IPv6", func(t *testing.T) {
		mux := connection.NewSrcMuxedConn()
		mockConn := new(MockConnection)
		mockConn.On("ReadPacket", mock.Anything).Return(0, []byte{}, nil).Maybe()

		prefix := netip.MustParsePrefix("2001:db8::/96")
		mux.Add(prefix, mockConn)

		pkt := make([]byte, 40)
		pkt[0] = 0x60                                                 // IPv6
		copy(pkt[8:24], netip.MustParseAddr("2001:db8::1").AsSlice()) // Source address

		mockConn.On("WritePacket", pkt).Return([]byte("ok"), nil).Once()

		resp, err := mux.WritePacket(pkt)
		assert.NoError(t, err)
		assert.Equal(t, []byte("ok"), resp)
		mockConn.AssertExpectations(t)
	})

	t.Run("WritePacket - Success with IPv4", func(t *testing.T) {
		mux := connection.NewSrcMuxedConn()
		mockConn := new(MockConnection)
		mockConn.On("ReadPacket", mock.Anything).Return(0, []byte{}, nil).Maybe()

		prefix := netip.MustParsePrefix("192.0.2.0/24")
		mux.Add(prefix, mockConn)

		pkt := make([]byte, 20)
		pkt[0] = 0x45                                                // IPv4
		copy(pkt[12:16], netip.MustParseAddr("192.0.2.1").AsSlice()) // Source address

		mockConn.On("WritePacket", pkt).Return([]byte("ok"), nil).Once()

		resp, err := mux.WritePacket(pkt)
		assert.NoError(t, err)
		assert.Equal(t, []byte("ok"), resp)
		mockConn.AssertExpectations(t)
	})

	t.Run("WritePacket - No Connection Found", func(t *testing.T) {
		mux := connection.NewSrcMuxedConn()

		pkt := make([]byte, 40)
		pkt[0] = 0x60
		copy(pkt[8:24], netip.MustParseAddr("2001:db8::1").AsSlice())

		resp, err := mux.WritePacket(pkt)
		assert.Nil(t, resp)
		assert.ErrorContains(t, err, "no matching tunnel")
	})

	t.Run("WritePacket - Invalid Packet", func(t *testing.T) {
		mux := connection.NewSrcMuxedConn()

		// Too short IPv6 packet
		pkt := make([]byte, 10)
		pkt[0] = 0x60

		resp, err := mux.WritePacket(pkt)
		assert.Nil(t, resp)
		assert.ErrorContains(t, err, "IPv6 packet too short")

		// Too short IPv4 packet
		pkt = make([]byte, 10)
		pkt[0] = 0x45

		resp, err = mux.WritePacket(pkt)
		assert.Nil(t, resp)
		assert.ErrorContains(t, err, "IPv4 packet too short")

		// Unknown packet type
		pkt = make([]byte, 20)
		pkt[0] = 0x00

		resp, err = mux.WritePacket(pkt)
		assert.Nil(t, resp)
		assert.ErrorContains(t, err, "unknown packet type")
	})
}
