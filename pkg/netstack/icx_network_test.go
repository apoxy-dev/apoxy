package netstack_test

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"gvisor.dev/gvisor/pkg/tcpip"

	"github.com/apoxy-dev/icx"

	"github.com/apoxy-dev/apoxy/pkg/netstack"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/bifurcate"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/l2pc"
)

func TestICXNetwork_Speed(t *testing.T) {
	if !testing.Verbose() {
		t.Skip("Not running speed test in non-verbose mode")
	}

	slog.SetLogLoggerLevel(slog.LevelDebug)

	// Create two underlying UDP packet conns on localhost
	pcA, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	pcAGeneve, _ := bifurcate.Bifurcate(pcA)

	pcB, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	pcBGeneve, _ := bifurcate.Bifurcate(pcB)

	// Wrap them as L2 adapters.
	l2A, err := l2pc.NewL2PacketConn(pcAGeneve)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, l2A.Close()) })

	l2B, err := l2pc.NewL2PacketConn(pcBGeneve)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, l2B.Close()) })

	uaA := pcA.LocalAddr().(*net.UDPAddr)
	uaB := pcB.LocalAddr().(*net.UDPAddr)

	aA := netip.AddrPortFrom(netip.MustParseAddr(uaA.IP.String()), uint16(uaA.Port))
	aB := netip.AddrPortFrom(netip.MustParseAddr(uaB.IP.String()), uint16(uaB.Port))

	// Build ICX handlers in L3 mode and link them together
	hA, err := icx.NewHandler(icx.WithLocalAddr(netstack.ToFullAddress(aA)),
		icx.WithVirtMAC(tcpip.GetRandMacAddr()), icx.WithLayer3VirtFrames())
	require.NoError(t, err)

	hB, err := icx.NewHandler(icx.WithLocalAddr(netstack.ToFullAddress(aB)),
		icx.WithVirtMAC(tcpip.GetRandMacAddr()), icx.WithLayer3VirtFrames())
	require.NoError(t, err)

	const vni = 0x424242

	// Advertise a shared /24 so each side routes via the tunnel.
	route := netip.MustParsePrefix("10.1.0.0/24")

	err = hA.AddVirtualNetwork(vni, netstack.ToFullAddress(aB), []netip.Prefix{route})
	require.NoError(t, err)

	err = hB.AddVirtualNetwork(vni, netstack.ToFullAddress(aA), []netip.Prefix{route})
	require.NoError(t, err)

	var key [16]byte
	copy(key[:], []byte("0123456789abcdef"))

	err = hA.UpdateVirtualNetworkKeys(vni, 1, key, key, time.Now().Add(time.Hour))
	require.NoError(t, err)

	err = hB.UpdateVirtualNetworkKeys(vni, 1, key, key, time.Now().Add(time.Hour))
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = hA.RemoveVirtualNetwork(vni)
		_ = hB.RemoveVirtualNetwork(vni)
	})

	// Create two networks on top of the handlers
	mtu := icx.MTU(1500) // compute the inner MTU based on the path MTU
	netA, err := netstack.NewICXNetwork(hA, l2A, mtu, nil, "")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, netA.Close()) })

	netB, err := netstack.NewICXNetwork(hB, l2B, mtu, nil, "")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, netB.Close()) })

	// Assign IPs on the same /24.
	ipA := netip.MustParsePrefix("10.1.0.1/24")
	ipB := netip.MustParsePrefix("10.1.0.2/24")
	require.NoError(t, netA.AddAddr(ipA))
	require.NoError(t, netB.AddAddr(ipB))

	// Start splicing packets
	go func() {
		var g errgroup.Group
		g.Go(netA.Start)
		g.Go(netB.Start)
		if err := g.Wait(); err != nil && !errors.Is(err, net.ErrClosed) {
			panic(fmt.Errorf("splice failed: %w", err))
		}
	}()

	// Start an HTTP server on A and hit it from B
	ln, err := netA.Listen("tcp", ipA.Addr().String()+":0")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, ln.Close()) })

	mux := http.NewServeMux()

	// /speed streams 100 MiB of random-looking data efficiently.
	const totalBytes = int64(100 << 20) // 100 MiB per stream
	const chunk = 1 << 20               // 1 MiB chunks
	randomBuf := make([]byte, chunk)
	_, err = rand.Read(randomBuf) // fill once; reuse buffer for speed
	require.NoError(t, err)

	mux.HandleFunc("/speed", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.FormatInt(totalBytes, 10))

		var sent int64
		for sent < totalBytes {
			remain := totalBytes - sent
			if remain < int64(len(randomBuf)) {
				_, _ = w.Write(randomBuf[:remain])
				sent += remain
				break
			}
			_, _ = w.Write(randomBuf)
			sent += int64(len(randomBuf))
		}
	})

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { require.NoError(t, srv.Close()) })

	// Build a client that dials via netB.
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: netB.DialContext,
		},
		Timeout: 30 * time.Second,
	}

	// Single-stream speed test
	t.Run("Speed", func(t *testing.T) {
		url := "http://" + ln.Addr().String() + "/speed"
		start := time.Now()

		resp, err := client.Get(url)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		n, err := io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		require.NoError(t, err)
		require.EqualValues(t, totalBytes, n, "unexpected byte count")

		elapsed := time.Since(start)
		sec := elapsed.Seconds()
		mbps := (float64(n) * 8) / 1_000_000 / sec
		gbps := (float64(n) * 8) / 1_000_000_000 / sec
		mbpsBytes := (float64(n)) / 1_000_000 / sec

		t.Logf("Downloaded %d bytes in %s → %.2f MB/s, %.2f Mbit/s (%.2f Gbit/s)",
			n, elapsed, mbpsBytes, mbps, gbps)
	})

	// Parallel speed test: four concurrent streams, each 200 MiB
	t.Run("SpeedParallel", func(t *testing.T) {
		const numStreams = 8
		URL := "http://" + ln.Addr().String() + "/speed"

		tr := &http.Transport{
			DialContext:         netB.DialContext,
			MaxConnsPerHost:     numStreams * 2,
			MaxIdleConns:        numStreams * 2,
			MaxIdleConnsPerHost: numStreams * 2,
			DisableCompression:  true,
			ForceAttemptHTTP2:   false,
		}
		defer tr.CloseIdleConnections()

		parallelClient := &http.Client{
			Transport: tr,
			Timeout:   2 * time.Minute,
		}

		start := time.Now()
		var g errgroup.Group

		for i := 0; i < numStreams; i++ {
			g.Go(func() error {
				resp, err := parallelClient.Get(URL)
				if err != nil {
					return err
				}
				if resp.StatusCode != http.StatusOK {
					_ = resp.Body.Close()
					return fmt.Errorf("status: %s", resp.Status)
				}
				n, err := io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if err != nil {
					return err
				}
				if n != totalBytes {
					return fmt.Errorf("unexpected byte count: got %d, want %d", n, totalBytes)
				}
				return nil
			})
		}
		require.NoError(t, g.Wait())

		totalRead := int64(numStreams) * totalBytes
		elapsed := time.Since(start)
		sec := elapsed.Seconds()
		mbps := (float64(totalRead) * 8) / 1_000_000 / sec
		gbps := (float64(totalRead) * 8) / 1_000_000_000 / sec
		mbpsBytes := (float64(totalRead)) / 1_000_000 / sec

		t.Logf("%d streams × %d bytes each: %d bytes in %s → %.2f MB/s, %.2f Mbit/s (%.2f Gbit/s)",
			numStreams, totalBytes, totalRead, elapsed, mbpsBytes, mbps, gbps)
	})
}
