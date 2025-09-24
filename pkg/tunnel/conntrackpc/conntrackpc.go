// Package conntrackpc provides a conntrack-style multiplexer for net.PacketConn,
// suitable for QUIC clients that want multiple "virtual" PacketConns over one UDP socket.
package conntrackpc

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
)

type Options struct {
	// If true, a new VirtualPacketConn is auto-created on the first inbound packet
	// seen from a remote address not yet in the table.
	AutoCreate bool

	// TTL is the idle timeout for a flow. If no traffic touches the flow for this duration,
	// it is evicted and closed by the cache.
	TTL time.Duration

	// MaxFlows bounds memory usage; oldest/expired flows are evicted first.
	MaxFlows int

	// Size of each per-flow inbound queue (non-blocking fanout).
	RxBufSize int

	// If true, vconn.WriteTo's addr parameter can change the remote and re-key the flow.
	AllowAddrOverrideOnWrite bool
}

func (o Options) withDefaults() Options {
	if o.TTL <= 0 {
		o.TTL = 2 * time.Minute
	}
	if o.MaxFlows <= 0 {
		o.MaxFlows = 1024
	}
	if o.RxBufSize <= 0 {
		o.RxBufSize = 64
	}
	return o
}

type ConntrackPacketConn struct {
	underlying net.PacketConn
	localAddr  net.Addr
	opts       Options

	mu      sync.RWMutex
	flows   *expirable.LRU[string, *VirtualPacketConn]
	closed  bool
	readErr error

	wg       sync.WaitGroup
	stopRead chan struct{}
}

func New(underlying net.PacketConn, opts Options) *ConntrackPacketConn {
	opts = opts.withDefaults()

	ct := &ConntrackPacketConn{
		underlying: underlying,
		localAddr:  underlying.LocalAddr(),
		opts:       opts,
		stopRead:   make(chan struct{}),
	}

	// Only close the flow if the evicted key is still the vconn's current key.
	// This makes removals during re-keying (oldKey removal) a no-op.
	onEvicted := func(k string, v *VirtualPacketConn) {
		if v != nil {
			// If v.key changed (due to re-key), skip closing.
			if v.key == k {
				_ = v.closeLocked(errFlowExpired)
			}
		}
	}
	ct.flows = expirable.NewLRU[string, *VirtualPacketConn](opts.MaxFlows, onEvicted, opts.TTL)

	ct.wg.Add(1)
	go ct.readLoop()

	return ct
}

func (c *ConntrackPacketConn) LocalAddr() net.Addr           { return c.localAddr }
func (c *ConntrackPacketConn) SetDeadline(t time.Time) error { return c.underlying.SetDeadline(t) }
func (c *ConntrackPacketConn) SetReadDeadline(t time.Time) error {
	return c.underlying.SetReadDeadline(t)
}
func (c *ConntrackPacketConn) SetWriteDeadline(t time.Time) error {
	return c.underlying.SetWriteDeadline(t)
}
func (c *ConntrackPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	return c.underlying.ReadFrom(b)
}
func (c *ConntrackPacketConn) WriteTo(b []byte, a net.Addr) (int, error) {
	return c.underlying.WriteTo(b, a)
}

func (c *ConntrackPacketConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	close(c.stopRead)

	// drain/close all flows by removing keys (triggers OnEvicted)
	keys := c.flows.Keys()
	c.mu.Unlock()

	for _, k := range keys {
		c.flows.Remove(k)
	}
	err := c.underlying.Close()
	c.wg.Wait()
	return err
}

// Open returns (or creates) a VirtualPacketConn bound to the provided remote.
func (c *ConntrackPacketConn) Open(remote *net.UDPAddr) (*VirtualPacketConn, error) {
	if remote == nil {
		return nil, errors.New("remote addr required")
	}
	key := remote.String()

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errConntrackClosed
	}

	if v, ok := c.flows.Get(key); ok && !v.isClosed() {
		// Refresh TTL by re-adding.
		c.flows.Add(key, v)
		return v, nil
	}

	v := newVirtual(c, key, remote, c.opts.RxBufSize)
	c.flows.Add(key, v)
	return v, nil
}

var (
	errConntrackClosed = errors.New("conntrack: closed")
	errFlowExpired     = errors.New("conntrack: flow expired")
)

func (c *ConntrackPacketConn) readLoop() {
	defer c.wg.Done()
	buf := make([]byte, 64*1024)

	for {
		select {
		case <-c.stopRead:
			return
		default:
		}

		n, from, err := c.underlying.ReadFrom(buf)
		if err != nil {
			c.mu.Lock()
			c.readErr = err
			// Close all flows
			for _, k := range c.flows.Keys() {
				if v, ok := c.flows.Peek(k); ok && v != nil {
					_ = v.closeLocked(err)
				}
			}
			c.mu.Unlock()
			return
		}
		if n == 0 {
			continue
		}

		key := from.String()

		c.mu.Lock()
		v, ok := c.flows.Get(key)
		if !ok {
			if !c.opts.AutoCreate {
				c.mu.Unlock()
				continue
			}
			udpFrom, _ := from.(*net.UDPAddr)
			v = newVirtual(c, key, udpFrom, c.opts.RxBufSize)
			c.flows.Add(key, v) // registers & sets TTL
		} else {
			// refresh TTL on activity
			c.flows.Add(key, v)
		}

		// non-blocking deliver; drop if back-pressured
		select {
		case v.inbound <- append([]byte(nil), buf[:n]...):
			v.touch()
		default:
			// drop to avoid HOL blocking
		}
		c.mu.Unlock()
	}
}

type VirtualPacketConn struct {
	parent   *ConntrackPacketConn
	key      string
	remote   *net.UDPAddr
	inbound  chan []byte
	closedCh chan struct{}

	rdMu          sync.Mutex
	rdDeadline    time.Time
	rdDeadlineSet bool

	wrMu          sync.Mutex
	wrDeadline    time.Time
	wrDeadlineSet bool
}

func newVirtual(parent *ConntrackPacketConn, key string, remote *net.UDPAddr, rx int) *VirtualPacketConn {
	return &VirtualPacketConn{
		parent:   parent,
		key:      key,
		remote:   cloneUDPAddr(remote),
		inbound:  make(chan []byte, rx),
		closedCh: make(chan struct{}),
	}
}

func (v *VirtualPacketConn) isClosed() bool {
	select {
	case <-v.closedCh:
		return true
	default:
		return false
	}
}

func (v *VirtualPacketConn) closeLocked(_ error) error {
	select {
	case <-v.closedCh:
		return nil
	default:
		close(v.closedCh)
		// drain inbound
		for {
			select {
			case <-v.inbound:
			default:
				return nil
			}
		}
	}
}

func (v *VirtualPacketConn) touch() {
	// Refresh TTL by re-adding into the LRU.
	v.parent.flows.Add(v.key, v)
}

func (v *VirtualPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	// Handle deadline
	timer := v.nextReadTimer()
	if timer != nil {
		defer timer.Stop()
	}

	select {
	case <-v.closedCh:
		return 0, nil, net.ErrClosed
	case <-timerC(timer):
		return 0, nil, timeoutErr("read")
	case pkt := <-v.inbound:
		v.touch()
		n := copy(b, pkt)
		return n, cloneUDPAddr(v.remote), nil
	}
}

func (v *VirtualPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if v.isClosed() {
		return 0, net.ErrClosed
	}
	remote := v.remote

	// Optional remote override + re-keying
	if v.parent.opts.AllowAddrOverrideOnWrite && addr != nil {
		if ua, ok := addr.(*net.UDPAddr); ok {
			newKey := ua.String()
			if newKey != v.key {
				// Re-key safely: update fields, add new key, then remove old key.
				v.parent.mu.Lock()
				oldKey := v.key
				v.key = newKey
				v.remote = cloneUDPAddr(ua)
				v.parent.flows.Add(newKey, v)
				v.parent.flows.Remove(oldKey) // onEvicted won't close us now
				v.parent.mu.Unlock()
			} else {
				v.remote = cloneUDPAddr(ua)
			}
			remote = ua
		}
	}

	// Respect write deadline by temporarily setting it on the shared socket.
	timer := v.nextWriteTimer()
	if timer != nil {
		defer timer.Stop()
	}
	if deadline, ok := v.getWriteDeadline(); ok {
		_ = v.parent.underlying.SetWriteDeadline(deadline)
		defer v.parent.underlying.SetWriteDeadline(time.Time{})
	}

	n, err := v.parent.underlying.WriteTo(b, remote)
	if err == nil {
		v.touch()
	}
	return n, err
}

func (v *VirtualPacketConn) Close() error {
	// Remove from LRU (will trigger OnEvicted -> closeLocked)
	v.parent.flows.Remove(v.key)
	return nil
}

func (v *VirtualPacketConn) LocalAddr() net.Addr { return v.parent.localAddr }

func (v *VirtualPacketConn) SetDeadline(t time.Time) error {
	_ = v.SetReadDeadline(t)
	_ = v.SetWriteDeadline(t)
	return nil
}
func (v *VirtualPacketConn) SetReadDeadline(t time.Time) error {
	v.rdMu.Lock()
	v.rdDeadline = t
	v.rdDeadlineSet = !t.IsZero()
	v.rdMu.Unlock()
	return nil
}
func (v *VirtualPacketConn) SetWriteDeadline(t time.Time) error {
	v.wrMu.Lock()
	v.wrDeadline = t
	v.wrDeadlineSet = !t.IsZero()
	v.wrMu.Unlock()
	return nil
}

func (v *VirtualPacketConn) nextReadTimer() *time.Timer {
	v.rdMu.Lock()
	defer v.rdMu.Unlock()
	if !v.rdDeadlineSet {
		return nil
	}
	d := time.Until(v.rdDeadline)
	if d <= 0 {
		d = time.Nanosecond
	}
	return time.NewTimer(d)
}
func (v *VirtualPacketConn) getWriteDeadline() (time.Time, bool) {
	v.wrMu.Lock()
	defer v.wrMu.Unlock()
	return v.wrDeadline, v.wrDeadlineSet
}
func (v *VirtualPacketConn) nextWriteTimer() *time.Timer {
	v.wrMu.Lock()
	defer v.wrMu.Unlock()
	if !v.wrDeadlineSet {
		return nil
	}
	d := time.Until(v.wrDeadline)
	if d <= 0 {
		d = time.Nanosecond
	}
	return time.NewTimer(d)
}

func timerC(t *time.Timer) <-chan time.Time {
	if t == nil {
		return nil
	}
	return t.C
}

func cloneUDPAddr(a *net.UDPAddr) *net.UDPAddr {
	if a == nil {
		return nil
	}
	out := *a
	if ip := a.IP; ip != nil {
		cp := make([]byte, len(ip))
		copy(cp, ip)
		out.IP = cp
	}
	return &out
}

func timeoutErr(op string) error {
	type t interface {
		Timeout() bool
		Error() string
	}
	return &net.OpError{Op: op, Err: errTimeout{}}
}

type errTimeout struct{}

func (errTimeout) Error() string   { return "i/o timeout" }
func (errTimeout) Timeout() bool   { return true }
func (errTimeout) Temporary() bool { return true }
