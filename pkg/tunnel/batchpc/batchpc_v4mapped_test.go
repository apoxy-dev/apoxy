package batchpc

import (
	"net"
	"testing"
	"time"
)

// TestWriteBatch_V4DstOnDualStackSocket exercises writing to a plain IPv4
// destination through a dual-stack ([::]) socket. x/net marshals the sockaddr
// family from the raw IP slice length, so without v4-mapped normalization the
// write fails with EINVAL on darwin while silently working on linux.
func TestWriteBatch_V4DstOnDualStackSocket(t *testing.T) {
	sender, err := net.ListenPacket("udp", ":0")
	if err != nil {
		t.Fatalf("listen sender: %v", err)
	}
	defer sender.Close()

	receiver, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen receiver: %v", err)
	}
	defer receiver.Close()

	bpc, err := New("udp", sender)
	if err != nil {
		t.Fatalf("wrap sender: %v", err)
	}

	dst := &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1).To4(),
		Port: receiver.LocalAddr().(*net.UDPAddr).Port,
	}
	payload := []byte("v4-mapped")
	n, err := bpc.WriteBatch([]Message{{Buf: payload, Addr: dst}}, 0)
	if err != nil {
		t.Fatalf("WriteBatch to v4 dst: %v", err)
	}
	if n != 1 {
		t.Fatalf("WriteBatch sent %d messages, want 1", n)
	}

	_ = receiver.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	rn, _, err := receiver.ReadFrom(buf)
	if err != nil {
		t.Fatalf("receiver read: %v", err)
	}
	if string(buf[:rn]) != string(payload) {
		t.Fatalf("received %q, want %q", buf[:rn], payload)
	}
}
