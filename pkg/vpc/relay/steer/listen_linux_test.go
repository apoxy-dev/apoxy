// SPDX-License-Identifier: AGPL-3.0-only

package steer

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pspwire "github.com/apoxy-dev/softpsp/psp"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

const sockets = 4

func listenUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func group(t *testing.T) []*net.UDPConn {
	t.Helper()
	conns, err := Listen("udp4", "127.0.0.1:0", sockets)
	require.NoError(t, err)
	t.Cleanup(func() {
		for _, c := range conns {
			_ = c.Close()
		}
	})
	return conns
}

// TestListen sends packets to the group from one source and checks which
// socket gets each one.
func TestListen(t *testing.T) {
	conns := group(t)
	type rx struct {
		socket int
		pkt    string
	}
	got := make(chan rx, 64)
	for i, c := range conns {
		go func() {
			buf := make([]byte, 2048)
			for {
				n, _, err := c.ReadFromUDP(buf)
				if err != nil {
					return
				}
				got <- rx{i, string(buf[:n])}
			}
		}()
	}
	src := listenUDP(t)
	to := conns[0].LocalAddr().(*net.UDPAddr)
	recv := func(pkt []byte) int {
		t.Helper()
		_, err := src.WriteToUDP(pkt, to)
		require.NoError(t, err)
		select {
		case r := <-got:
			require.Equal(t, string(pkt), r.pkt)
			return r.socket
		case <-time.After(5 * time.Second):
			t.Fatal("no socket got the packet in 5 s")
			return -1
		}
	}
	for i := range 2 * sockets {
		id := []byte{byte(i), 1, 2, 3, 4, 5, 6, 7}
		assert.Equal(t, i%sockets, recv(shortHeader(id)), "short header to ID %d", i)
		assert.Equal(t, i%sockets, recv(longHeader(id)), "long header to ID %d", i)
	}
	// Packets that fall to the hash go to one socket for one source.
	hashed := [][]byte{
		append([]byte{pspwire.NextHdrV4}, make([]byte, 40)...),
		append([]byte{pspwire.NextHdrV6}, make([]byte, 40)...),
		append([]byte{0x02}, make([]byte, 40)...),
		longHeader(nil),
		{0x41},
	}
	first := recv(hashed[0])
	for _, pkt := range hashed[1:] {
		assert.Equal(t, first, recv(pkt), "packet %x", pkt[:1])
	}
}

func TestListenSockets(t *testing.T) {
	for _, n := range []int{0, MaxSockets + 1} {
		_, err := Listen("udp4", "127.0.0.1:0", n)
		assert.Error(t, err, "n %d", n)
	}
}

// countConn counts the packets that a socket reads. It hides the batch and
// OOB methods, so quic-go reads with ReadFrom.
type countConn struct {
	net.PacketConn
	n atomic.Int64
}

func (c *countConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(b)
	if err == nil {
		c.n.Add(1)
	}
	return n, addr, err
}

// rebinder forwards UDP between one agent and the relay, as a NAT does.
// rebind moves it to a new source port.
type rebinder struct {
	t     *testing.T
	front *net.UDPConn
	agent atomic.Pointer[net.UDPAddr]
	outer atomic.Pointer[net.UDPConn]
}

func newRebinder(t *testing.T, relay *net.UDPAddr) *rebinder {
	r := &rebinder{t: t, front: listenUDP(t)}
	r.rebind()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := r.front.ReadFromUDP(buf)
			if err != nil {
				return
			}
			r.agent.Store(from)
			_, _ = r.outer.Load().WriteToUDP(buf[:n], relay)
		}
	}()
	return r
}

func (r *rebinder) rebind() {
	oc := listenUDP(r.t)
	r.outer.Store(oc)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, _, err := oc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if a := r.agent.Load(); a != nil {
				_, _ = r.front.WriteToUDP(buf[:n], a)
			}
		}
	}()
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "relay.test"},
		DNSNames:     []string{"relay.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// ping sends one datagram on qc and returns the relay socket that echoed it.
func ping(qc quic.Connection) (int, error) {
	ctx, cancel := context.WithTimeout(qc.Context(), 2*time.Second)
	defer cancel()
	if err := qc.SendDatagram([]byte("ping")); err != nil {
		return -1, err
	}
	b, err := qc.ReceiveDatagram(ctx)
	if err != nil {
		return -1, err
	}
	return int(b[0]), nil
}

// TestRebind runs agents with 4 connections on one socket through a NAT that
// changes port. A packet on the wrong relay socket gets a stateless reset.
func TestRebind(t *testing.T) {
	const (
		agents = 16
		shards = 4
		pings  = 5
	)
	cases := []struct {
		name    string
		program bool
	}{
		{"program", true},
		{"no program", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true")
			conns := group(t)
			if !tc.program {
				rc, err := conns[0].SyscallConn()
				require.NoError(t, err)
				require.NoError(t, control(rc, func(fd int) error {
					return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DETACH_REUSEPORT_BPF, 0)
				}))
			}
			var key quic.StatelessResetKey
			_, _ = rand.Read(key[:])
			counts := make([]*countConn, sockets)
			stc := &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}, NextProtos: []string{"test"}}
			for i, c := range conns {
				counts[i] = &countConn{PacketConn: c}
				tr := &quic.Transport{Conn: counts[i], ConnectionIDGenerator: ConnIDs{Index: uint8(i)}, StatelessResetKey: &key}
				t.Cleanup(func() { _ = tr.Close() })
				ln, err := tr.Listen(stc, &quic.Config{EnableDatagrams: true})
				require.NoError(t, err)
				go func() {
					for {
						qc, err := ln.Accept(context.Background())
						if err != nil {
							return
						}
						go func() {
							for {
								b, err := qc.ReceiveDatagram(qc.Context())
								if err != nil {
									return
								}
								_ = qc.SendDatagram(append([]byte{byte(i)}, b...))
							}
						}()
					}
				}()
			}

			relay := conns[0].LocalAddr().(*net.UDPAddr)
			nats := make([]*rebinder, agents)
			qcs := make([][]quic.Connection, agents)
			ctc := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"test"}}
			for a := range agents {
				nats[a] = newRebinder(t, relay)
				tr := &quic.Transport{Conn: listenUDP(t)}
				t.Cleanup(func() { _ = tr.Close() })
				for range shards {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					qc, err := tr.Dial(ctx, nats[a].front.LocalAddr(), ctc, &quic.Config{EnableDatagrams: true})
					cancel()
					require.NoError(t, err)
					t.Cleanup(func() { _ = qc.CloseWithError(0, "") })
					qcs[a] = append(qcs[a], qc)
				}
			}

			// pingAll pings on each connection and returns the relay socket of
			// each, or -1 for a connection that failed.
			pingAll := func() [][]int {
				out := make([][]int, agents)
				var wg sync.WaitGroup
				for a := range agents {
					out[a] = make([]int, shards)
					for s, qc := range qcs[a] {
						wg.Go(func() {
							out[a][s] = -1
							for range pings {
								i, err := ping(qc)
								if err != nil || (out[a][s] >= 0 && i != out[a][s]) {
									out[a][s] = -1
									return
								}
								out[a][s] = i
							}
						})
					}
				}
				wg.Wait()
				return out
			}

			before := pingAll()
			perSocket := make([]int, sockets)
			spread := 0
			for a, socks := range before {
				used := map[int]bool{}
				for s, i := range socks {
					require.GreaterOrEqual(t, i, 0, "agent %d connection %d failed before the rebind", a, s)
					used[i] = true
					perSocket[i]++
				}
				if len(used) > 1 {
					spread++
				}
			}
			for _, nat := range nats {
				nat.rebind()
			}
			after := pingAll()
			moved, failed := 0, 0
			for a := range agents {
				for s := range shards {
					switch i := after[a][s]; {
					case i < 0:
						failed++
					case i != before[a][s]:
						moved++
					}
				}
			}
			packets := make([]int64, sockets)
			for i, c := range counts {
				packets[i] = c.n.Load()
			}
			t.Logf("Connections on each socket: %v; agents with connections on 2 or more sockets: %d of %d", perSocket, spread, agents)
			t.Logf("Packets read by each socket: %v; after the rebind %d of %d connections failed", packets, failed, agents*shards)
			assert.Zero(t, moved, "a connection moved to another socket")
			if tc.program {
				assert.GreaterOrEqual(t, spread, agents*3/4)
				for i, n := range perSocket {
					assert.NotZero(t, n, "socket %d got no connection", i)
				}
				assert.Zero(t, failed)
			} else {
				assert.Zero(t, spread, "without the program, the connections of an agent share one socket")
				assert.NotZero(t, failed, "without the program, a rebind ends connections")
			}
		})
	}
}
