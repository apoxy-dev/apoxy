package connection_test

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apoxy-dev/apoxy-cli/pkg/cryptoutils"
	"github.com/apoxy-dev/apoxy-cli/pkg/netstack"
	"github.com/apoxy-dev/apoxy-cli/pkg/tunnel/connection"
	"github.com/apoxy-dev/apoxy-cli/pkg/tunnel/fasttun"
	tunnet "github.com/apoxy-dev/apoxy-cli/pkg/tunnel/net"
	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/require"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/sync/errgroup"
)

func TestConnectIPDeviceThroughput(t *testing.T) {
	prefix := netip.MustParsePrefix("fd00::/64")
	template := uritemplate.MustNew("https://proxy/connect/")

	caCert, serverCert, err := cryptoutils.GenerateSelfSignedTLSCert("proxy")
	require.NoError(t, err)

	/*	f, err := os.Create("cpu.prof")
		require.NoError(t, err)
		t.Cleanup(func() { _ = f.Close() })
		pprof.StartCPUProfile(f)
		t.Cleanup(pprof.StopCPUProfile)*/

	g, ctx := errgroup.WithContext(t.Context())

	// Server
	g.Go(func() error {
		udpConn, err := net.ListenUDP("udp", &net.UDPAddr{
			IP:   net.IPv4(127, 0, 0, 1),
			Port: 8443,
		})
		if err != nil {
			return fmt.Errorf("failed to listen on UDP: %w", err)
		}
		defer udpConn.Close()

		ln, err := quic.ListenEarly(
			udpConn,
			http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{serverCert}}),
			&quic.Config{EnableDatagrams: true},
		)
		if err != nil {
			return fmt.Errorf("failed to listen on QUIC: %w", err)
		}
		defer ln.Close()

		p := connectip.Proxy{}
		mux := http.NewServeMux()

		mux.HandleFunc("/connect/", func(w http.ResponseWriter, r *http.Request) {
			req, err := connectip.ParseRequest(r, template)
			if err != nil {
				slog.Error("Failed to parse request", slog.Any("error", err))
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			conn, err := p.Proxy(w, req)
			if err != nil {
				slog.Error("Failed to proxy request", slog.Any("error", err))
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			defer conn.Close()

			if err := conn.AssignAddresses(r.Context(), []netip.Prefix{
				netip.MustParsePrefix("fd00::2/128"),
			}); err != nil {
				slog.Error("Failed to assign address", slog.Any("error", err))
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			if err := conn.AdvertiseRoute(r.Context(), []connectip.IPRoute{
				{
					StartIP: prefix.Addr(),
					EndIP:   tunnet.LastIP(prefix),
				},
			}); err != nil {
				slog.Error("Failed to advertise route", slog.Any("error", err))
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			dev := connection.NewDevice(conn)

			g, ctx := errgroup.WithContext(r.Context())

			numQueues := 1 //runtime.NumCPU()
			for i := 0; i < numQueues; i++ {
				queue, err := dev.NewPacketQueue()
				if err != nil {
					slog.Error("Failed to create packet queue", slog.Int("queue", i), slog.Any("error", err))
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				g.Go(func() error {
					return receivePackets(ctx, queue, numQueues)
				})
			}

			if err := g.Wait(); err != nil && !(errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled)) {
				slog.Error("Error waiting for packets", slog.Any("error", err))
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		})

		s := http3.Server{
			Handler:         mux,
			EnableDatagrams: true,
		}
		defer s.Close()

		g.Go(func() error {
			<-ctx.Done()
			return s.Shutdown(t.Context())
		})

		return s.ServeListener(ln)
	})

	// Client
	g.Go(func() error {
		time.Sleep(1 * time.Second) // Wait for server to come up

		tlsConfig := &tls.Config{
			ServerName: "proxy",
			NextProtos: []string{http3.NextProtoH3},
			RootCAs:    cryptoutils.CertPoolForCertificate(caCert),
		}

		qConn, err := quic.DialAddr(
			ctx,
			"localhost:8443",
			tlsConfig,
			&quic.Config{
				EnableDatagrams:   true,
				InitialPacketSize: 1350,
				KeepAlivePeriod:   5 * time.Second,
				MaxIdleTimeout:    5 * time.Minute,
			},
		)
		if err != nil {
			return fmt.Errorf("failed to dial QUIC connection: %w", err)
		}
		defer qConn.CloseWithError(0, "done")

		tr := &http3.Transport{EnableDatagrams: true}
		hconn := tr.NewClientConn(qConn)

		conn, rsp, err := connectip.Dial(ctx, hconn, template)
		if err != nil {
			return fmt.Errorf("failed to dial connect-ip connection: %w", err)
		}
		if rsp.StatusCode != http.StatusOK {
			return fmt.Errorf("unexpected status code: %d", rsp.StatusCode)
		}
		defer conn.Close()

		dev := connection.NewDevice(conn)

		g, ctx := errgroup.WithContext(ctx)

		var sentBytes atomic.Int64

		numQueues := runtime.NumCPU()
		for i := 0; i < numQueues; i++ {
			pq, err := dev.NewPacketQueue()
			if err != nil {
				return fmt.Errorf("failed to create packet queue %d: %w", i, err)
			}

			g.Go(func() error {
				return sendPackets(ctx, pq, &sentBytes)
			})
		}

		if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
			return fmt.Errorf("error sending packets: %w", err)
		}

		slog.Info("Sent packets", slog.Int64("sent_bytes", sentBytes.Load()))

		return context.Canceled
	})

	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func receivePackets(ctx context.Context, pq fasttun.PacketQueue, numQueues int) error {
	defer pq.Close()

	buf := make([][]byte, 1)
	sizes := make([]int, 1)
	buf[0] = make([]byte, netstack.IPv6MinMTU)

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		n, err := pq.Read(buf, sizes)
		if err != nil {
			// Only one thread receives the net.ErrClosed error, and without context
			// support there's no clean way to stop the other threads.
			if numQueues > 1 && errors.Is(err, net.ErrClosed) {
				os.Exit(0)
			}

			return err
		}
		if n == 0 {
			continue
		}
	}
}

func sendPackets(ctx context.Context, pq fasttun.PacketQueue, sentBytes *atomic.Int64) error {
	defer pq.Close()

	payload := make([]byte, 1232)
	for i := range payload {
		payload[i] = 'X'
	}

	packet, err := buildIPv6UDPPacket(
		netip.MustParseAddr("fd00::2"),
		netip.MustParseAddr("fd00::1"),
		1234, 5678,
		payload,
	)
	if err != nil {
		return err
	}

	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()

	pkts := make([][]byte, 1)
	pkts[0] = make([]byte, netstack.IPv6MinMTU)

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-deadline.C:
			return nil
		default:
		}

		pkts[0] = pkts[0][:netstack.IPv6MinMTU]
		n := copy(pkts[0], packet)
		pkts[0] = pkts[0][:n]

		if _, err := pq.Write(pkts); err != nil {
			return fmt.Errorf("failed to write packet: %w", err)
		}
		sentBytes.Add(int64(len(pkts[0])))
	}
}

func buildIPv6UDPPacket(src, dst netip.Addr, srcPort, dstPort int, udpPayload []byte) ([]byte, error) {
	udpLen := 8 + len(udpPayload)
	udpHeader := make([]byte, 8)
	binary.BigEndian.PutUint16(udpHeader[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(udpHeader[2:4], uint16(dstPort))
	binary.BigEndian.PutUint16(udpHeader[4:6], uint16(udpLen))

	ipHeader := make([]byte, 40)
	ipHeader[0] = (6 << 4)
	binary.BigEndian.PutUint16(ipHeader[4:6], uint16(udpLen))
	ipHeader[6] = 17
	ipHeader[7] = 64
	copy(ipHeader[8:24], src.AsSlice())
	copy(ipHeader[24:40], dst.AsSlice())

	packet := append(ipHeader, udpHeader...)
	packet = append(packet, udpPayload...)

	return packet, nil
}
