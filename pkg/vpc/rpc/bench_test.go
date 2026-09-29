// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package rpc_test

import (
	"context"
	"fmt"
	"io"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc/internal/testpb"
)

// cpuTime returns the user and system CPU time of the process.
func cpuTime() time.Duration {
	var ru syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

// run runs f b.N times and reports the process CPU time per operation. Both
// ends of the connection run in this process, so cpu-ns/op is the cost of
// the caller and the called side together.
func run(b *testing.B, parallel bool, f func() error) {
	b.ReportAllocs()
	b.ResetTimer()
	start := cpuTime()
	if parallel {
		b.SetParallelism(8)
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				if err := f(); err != nil {
					b.Error(err)
					return
				}
			}
		})
	} else {
		for range b.N {
			if err := f(); err != nil {
				b.Fatal(err)
			}
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(cpuTime()-start)/float64(b.N), "cpu-ns/op")
}

// BenchmarkUnary measures the cost of one unary call: stream open, header,
// request, response, status.
func BenchmarkUnary(b *testing.B) {
	cases := []struct {
		name     string
		size     int
		parallel bool
		timeout  time.Duration
	}{
		{"serial/64B", 64, false, 0},
		{"serial/1KiB", 1024, false, 0},
		{"serial/64B-deadline", 64, false, 5 * time.Second},
		{"parallel/64B", 64, true, 0},
		{"parallel/1KiB", 1024, true, 0},
		{"parallel/64B-deadline", 64, true, 5 * time.Second},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			p := newPair(b, pairConfig{})
			c := testpb.NewEchoClient(p.dialer)
			req := &testpb.EchoRequest{Text: "bench", Payload: make([]byte, tc.size)}
			run(b, tc.parallel, func() error {
				ctx := context.Background()
				if tc.timeout > 0 {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, tc.timeout)
					defer cancel()
				}
				_, err := c.Unary(ctx, req)
				return err
			})
		})
	}
}

// BenchmarkRawQUIC is the quic-go baseline for BenchmarkUnary and
// BenchmarkStreamMessage: the same exchanges without this package.
func BenchmarkRawQUIC(b *testing.B) {
	b.Run("stream per call", func(b *testing.B) {
		p := newPair(b, pairConfig{noListenerServer: true})
		go func() {
			for {
				str, err := p.lq.AcceptStream(context.Background())
				if err != nil {
					return
				}
				go func() {
					buf, _ := io.ReadAll(str)
					_, _ = str.Write(buf)
					_ = str.Close()
				}()
			}
		}()
		msg := make([]byte, 64)
		run(b, false, func() error {
			str, err := p.dq.OpenStreamSync(context.Background())
			if err != nil {
				return err
			}
			if _, err := str.Write(msg); err != nil {
				return err
			}
			_ = str.Close()
			_, err = io.ReadAll(str)
			return err
		})
	})
	b.Run("ping-pong", func(b *testing.B) {
		p := newPair(b, pairConfig{noListenerServer: true})
		msg := make([]byte, 64)
		str, err := p.dq.OpenStreamSync(context.Background())
		if err != nil {
			b.Fatal(err)
		}
		if _, err := str.Write(msg); err != nil {
			b.Fatal(err)
		}
		srv, err := p.lq.AcceptStream(context.Background())
		if err != nil {
			b.Fatal(err)
		}
		go func() {
			buf := make([]byte, 64)
			for {
				if _, err := io.ReadFull(srv, buf); err != nil {
					return
				}
				if _, err := srv.Write(buf); err != nil {
					return
				}
			}
		}()
		if _, err := io.ReadFull(str, msg); err != nil {
			b.Fatal(err)
		}
		run(b, false, func() error {
			if _, err := str.Write(msg); err != nil {
				return err
			}
			_, err := io.ReadFull(str, msg)
			return err
		})
	})
}

// BenchmarkUnaryRate runs b.N unary calls at a fixed rate, spread over conns
// connections, and reports the CPU cores that the process used and the call
// latency. Each call has a 5 s deadline, as a setup call would.
func BenchmarkUnaryRate(b *testing.B) {
	cases := []struct {
		rate  int
		conns int
	}{
		{5000, 1},
		{5000, 16},
	}
	for _, tc := range cases {
		b.Run(fmt.Sprintf("%d-per-s/%d-conns", tc.rate, tc.conns), func(b *testing.B) {
			var clients []testpb.EchoClient
			for range tc.conns {
				clients = append(clients, testpb.NewEchoClient(newPair(b, pairConfig{}).dialer))
			}
			req := &testpb.EchoRequest{Text: "bench", Payload: make([]byte, 200)}
			work := make(chan int, 1024)
			lat := make([]time.Duration, b.N)
			var wg sync.WaitGroup
			for range 64 {
				wg.Go(func() {
					for i := range work {
						ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
						start := time.Now()
						if _, err := clients[i%len(clients)].Unary(ctx, req); err != nil {
							b.Error(err)
						}
						lat[i] = time.Since(start)
						cancel()
					}
				})
			}
			interval := time.Second / time.Duration(tc.rate)
			b.ResetTimer()
			cpu0, start := cpuTime(), time.Now()
			for i := range b.N {
				if d := time.Until(start.Add(time.Duration(i) * interval)); d > 0 {
					time.Sleep(d)
				}
				work <- i
			}
			close(work)
			wg.Wait()
			wall, cpu := time.Since(start), cpuTime()-cpu0
			b.StopTimer()
			slices.Sort(lat)
			b.ReportMetric(float64(cpu)/float64(wall), "cores")
			b.ReportMetric(float64(cpu)/float64(b.N), "cpu-ns/op")
			b.ReportMetric(float64(lat[len(lat)/2].Microseconds()), "p50-us")
			b.ReportMetric(float64(lat[len(lat)*99/100].Microseconds()), "p99-us")
		})
	}
}

// BenchmarkStreamMessage measures the cost of one message on an open stream.
func BenchmarkStreamMessage(b *testing.B) {
	b.Run("server stream", func(b *testing.B) {
		p := newPair(b, pairConfig{})
		c := testpb.NewEchoClient(p.dialer)
		st, err := c.ServerStream(context.Background(), &testpb.EchoRequest{Text: "bench", Count: uint32(b.N), Payload: make([]byte, 64)})
		if err != nil {
			b.Fatal(err)
		}
		run(b, false, func() error {
			_, err := st.Recv()
			return err
		})
		if _, err := st.Recv(); err != io.EOF {
			b.Fatal(err)
		}
	})
	b.Run("bidi ping-pong", func(b *testing.B) {
		p := newPair(b, pairConfig{})
		c := testpb.NewEchoClient(p.dialer)
		st, err := c.Bidi(context.Background())
		if err != nil {
			b.Fatal(err)
		}
		req := &testpb.EchoRequest{Text: "bench", Payload: make([]byte, 64)}
		run(b, false, func() error {
			if err := st.Send(req); err != nil {
				return err
			}
			_, err := st.Recv()
			return err
		})
		_ = st.CloseSend()
		if _, err := st.Recv(); err != io.EOF {
			b.Fatal(fmt.Errorf("got %v, want io.EOF", err))
		}
	})
}
