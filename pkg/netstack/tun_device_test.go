package netstack_test

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/dpeckett/network"

	"github.com/apoxy-dev/apoxy/pkg/netstack"
)

// spliceDevices connects two tun.Device endpoints entirely in memory.
// It pumps packets in both directions until either side closes.
func spliceDevices(ctx context.Context, a, b tun.Device) error {
	var g errgroup.Group

	g.Go(func() error { return pump(ctx, a, b) })
	g.Go(func() error { return pump(ctx, b, a) })

	return g.Wait()
}

func pump(ctx context.Context, src, dst tun.Device) error {
	mtu, _ := src.MTU()

	batchSize := min(src.BatchSize(), dst.BatchSize())
	bufs := make([][]byte, batchSize)
	sizes := make([]int, batchSize)
	for i := 0; i < batchSize; i++ {
		bufs[i] = make([]byte, mtu)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		n, err := src.Read(bufs, sizes, 0)
		if err != nil {
			// surface clean closure as nil
			if errors.Is(err, os.ErrClosed) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if n == 0 || sizes[0] == 0 {
			continue
		}

		packet := bufs[0][:sizes[0]]
		_, err = dst.Write([][]byte{packet}, 0)
		if err != nil {
			if errors.Is(err, os.ErrClosed) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
	}
}

func TestTunDevice_Speed(t *testing.T) {
	if !testing.Verbose() {
		t.Skip("Not running speed test in non-verbose mode")
	}

	slog.SetLogLoggerLevel(slog.LevelDebug)

	// Create two in-memory TunDevices
	tunA, err := netstack.NewTunDevice("") // no pcap
	require.NoError(t, err)
	t.Cleanup(func() { _ = tunA.Close() })

	tunB, err := netstack.NewTunDevice("")
	require.NoError(t, err)
	t.Cleanup(func() { _ = tunB.Close() })

	// Assign addresses on the same /24
	ipA := netip.MustParsePrefix("10.1.0.1/24")
	ipB := netip.MustParsePrefix("10.1.0.2/24")
	require.NoError(t, tunA.AddAddr(ipA))
	require.NoError(t, tunB.AddAddr(ipB))

	// Build standard-net adapters on top of the stacks exposed by TunDevice.
	// Your github.com/dpeckett/network package exposes a net-compatible API.
	var netA, netB *network.NetstackNetwork
	netA = tunA.Network(nil)
	netB = tunB.Network(nil)

	// Start the in-memory splicer
	spliceCtx, spliceCancel := context.WithCancel(context.Background())
	t.Cleanup(spliceCancel)

	var spliceErr error
	var spliceWG sync.WaitGroup
	spliceWG.Add(1)
	go func() {
		defer spliceWG.Done()
		spliceErr = spliceDevices(spliceCtx, tunA, tunB)
	}()
	t.Cleanup(func() {
		spliceCancel()
		spliceWG.Wait()
		require.True(t, spliceErr == nil || errors.Is(spliceErr, context.Canceled), "splice error: %v", spliceErr)
	})

	// HTTP server on A
	ln, err := netA.Listen("tcp", ipA.Addr().String()+":0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	mux := http.NewServeMux()

	// /speed streams 100 MiB quickly using a re-used random buffer.
	const totalBytes = int64(100 << 20) // 100 MiB
	const chunk = 1 << 20               // 1 MiB chunks
	randomBuf := make([]byte, chunk)
	_, err = rand.Read(randomBuf)
	require.NoError(t, err)

	mux.HandleFunc("/speed", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.FormatInt(totalBytes, 10))
		var sent int64
		for sent < totalBytes {
			remain := totalBytes - sent
			if remain < int64(len(randomBuf)) {
				_, _ = w.Write(randomBuf[:remain])
				break
			}
			_, _ = w.Write(randomBuf)
			sent += int64(len(randomBuf))
		}
	})

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	// HTTP client that dials via B’s stack.
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: netB.DialContext,
			// keep it simple for the single-stream run
			ForceAttemptHTTP2:  false,
			DisableCompression: true,
		},
		Timeout: 45 * time.Second,
	}

	// Single-stream speed test
	t.Run("Speed", func(t *testing.T) {
		url := "http://" + ln.Addr().String() + "/speed"
		start := time.Now()

		resp, err := client.Get(url)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		n, err := io.Copy(io.Discard, resp.Body)
		require.NoError(t, err)
		require.EqualValues(t, totalBytes, n, "unexpected byte count")

		elapsed := time.Since(start)
		sec := elapsed.Seconds()
		mbps := (float64(n) * 8) / 1_000_000 / sec
		gbps := (float64(n) * 8) / 1_000_000_000 / sec
		mbpsBytes := (float64(n)) / 1_000_000 / sec

		t.Logf("1 stream: %d bytes in %s → %.2f MB/s, %.2f Mbit/s (%.2f Gbit/s)",
			n, elapsed, mbpsBytes, mbps, gbps)
	})

	// Parallel speed test: multiple concurrent streams, each 200 MiB
	t.Run("SpeedParallel", func(t *testing.T) {
		const numStreams = 8
		url := "http://" + ln.Addr().String() + "/speed"

		tr := &http.Transport{
			DialContext:         netB.DialContext,
			MaxConnsPerHost:     numStreams * 2,
			MaxIdleConns:        numStreams * 2,
			MaxIdleConnsPerHost: numStreams * 2,
			DisableCompression:  true,
			ForceAttemptHTTP2:   false,
		}
		defer tr.CloseIdleConnections()

		parClient := &http.Client{
			Transport: tr,
			Timeout:   2 * time.Minute,
		}

		start := time.Now()
		var g errgroup.Group
		for i := 0; i < numStreams; i++ {
			g.Go(func() error {
				resp, err := parClient.Get(url)
				if err != nil {
					return err
				}
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					return fmt.Errorf("status: %s", resp.Status)
				}
				n, err := io.Copy(io.Discard, resp.Body)
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

		t.Logf("%d streams × %d bytes: %d bytes in %s → %.2f MB/s, %.2f Mbit/s (%.2f Gbit/s)",
			numStreams, totalBytes, totalRead, elapsed, mbpsBytes, mbps, gbps)
	})
}

// TestTunDevice_BoundSourceIsPreserved checks that a UDP socket bound to one
// of the local overlay addresses keeps that address on the wire. The SNAT
// postrouting rule must not move the socket to a sibling address, and the
// address set must stay consistent while it is changed concurrently.
func TestTunDevice_BoundSourceIsPreserved(t *testing.T) {
	tunA, err := netstack.NewTunDevice("")
	require.NoError(t, err)

	tunB, err := netstack.NewTunDevice("")
	require.NoError(t, err)

	// Several addresses on A, so that a random pick has something wrong to
	// pick.
	boundA := []netip.Prefix{
		netip.MustParsePrefix("fd00:1::1/64"),
		netip.MustParsePrefix("fd00:1::2/64"),
		netip.MustParsePrefix("fd00:1::3/64"),
	}
	// One more address that is added and removed while traffic runs.
	churnA := netip.MustParsePrefix("fd00:1::4/64")
	addrB := netip.MustParsePrefix("fd00:1::9/64")

	for _, addr := range boundA {
		require.NoError(t, tunA.AddAddr(addr))
	}
	require.NoError(t, tunB.AddAddr(addrB))

	spliceCtx, spliceCancel := context.WithCancel(context.Background())
	var spliceWG sync.WaitGroup
	spliceWG.Add(1)
	go func() {
		defer spliceWG.Done()
		_ = spliceDevices(spliceCtx, tunA, tunB)
	}()
	// Close the devices before waiting: the pumps block on a device read and
	// only a close wakes them.
	t.Cleanup(func() {
		spliceCancel()
		_ = tunA.Close()
		_ = tunB.Close()
		spliceWG.Wait()
	})

	// Change the address set while the sockets send, so that a reader of the
	// set sees it move under it.
	churnCtx, churnCancel := context.WithCancel(context.Background())
	var churnWG sync.WaitGroup
	churnWG.Add(1)
	go func() {
		defer churnWG.Done()
		for churnCtx.Err() == nil {
			if err := tunA.AddAddr(churnA); err != nil {
				return
			}
			if err := tunA.DelAddr(churnA); err != nil {
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
	t.Cleanup(func() {
		churnCancel()
		churnWG.Wait()
	})

	for _, addr := range boundA {
		t.Run(addr.Addr().String(), func(t *testing.T) {
			// A receiver per case, so that a retried datagram cannot be read
			// by the next case.
			recv, err := tunB.ListenPacket(netip.AddrPortFrom(addrB.Addr(), 0))
			require.NoError(t, err)
			t.Cleanup(func() { _ = recv.Close() })

			dst := &net.UDPAddr{
				IP:   addrB.Addr().AsSlice(),
				Port: recv.LocalAddr().(*net.UDPAddr).Port,
			}

			send, err := tunA.ListenPacket(netip.AddrPortFrom(addr.Addr(), 0))
			require.NoError(t, err)
			t.Cleanup(func() { _ = send.Close() })

			// UDP is lossy, so send until one datagram arrives.
			buf := make([]byte, 64)
			var src net.Addr
			deadline := time.Now().Add(10 * time.Second)
			for {
				require.False(t, time.Now().After(deadline), "no datagram arrived on B")

				_, err = send.WriteTo([]byte("ping"), dst)
				require.NoError(t, err)

				require.NoError(t, recv.SetReadDeadline(time.Now().Add(500*time.Millisecond)))
				_, src, err = recv.ReadFrom(buf)
				if err == nil {
					break
				}
				var netErr net.Error
				require.True(t, errors.As(err, &netErr) && netErr.Timeout(), "read failed: %v", err)
			}

			gotAddr, ok := netip.AddrFromSlice(src.(*net.UDPAddr).IP)
			require.True(t, ok, "bad source address %s", src)
			require.Equal(t, addr.Addr(), gotAddr.Unmap(),
				"source address was rewritten away from the bound address")
		})
	}
}
