package envoy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Missing eager listener/HCM stats must disable idle exit.
const drainStatsFilter = `downstream_(rq_active|rq_total|cx_active|pre_cx_active|cx_tx_bytes_buffered)$`

// The bootstrap's static readiness listener; its probes never stop during a drain.
const (
	readyListenerScope = "0.0.0.0_19001"
	readyHCMScope      = "eg-ready-http"
)

// errUDPListener disables the idle exit: the gauges do not count UDP sessions.
var errUDPListener = errors.New("UDP listener")

const dynamicListenerType = "type.googleapis.com/envoy.admin.v3.ListenersConfigDump.DynamicListener"

// perThreadScope matches the per-worker and main-thread listener scopes, which
// double count the aggregate one.
var perThreadScope = regexp.MustCompile(`\.(worker_[0-9]+|main_thread)$`)

// drainGauges sums the non-admin downstream gauges of one poll.
type drainGauges struct {
	RqActive   int64
	RqTotal    int64
	HCMCx      int64
	ListenerCx int64
	PreCx      int64
	TxBuffered int64
}

// idle reports whether no request, no non-HTTP connection, no connection in
// the listener filters and no unsent response byte exists.
func (g drainGauges) idle() bool {
	return g.RqActive == 0 &&
		g.PreCx == 0 &&
		g.ListenerCx == g.HCMCx &&
		(!drainCheckTxBuffered || g.TxBuffered == 0)
}

// idleTracker ends the drain once every poll for the quiet period was idle and
// no request arrived.
type idleTracker struct {
	quiet   time.Duration
	since   time.Time
	rqTotal int64
}

func (t *idleTracker) observe(now time.Time, g drainGauges, err error) bool {
	if err != nil || !g.idle() {
		t.since = time.Time{}
		return false
	}
	if t.since.IsZero() || g.RqTotal != t.rqTotal {
		t.since, t.rqTotal = now, g.RqTotal
	}
	return now.Sub(t.since) >= t.quiet
}

// pollDrainGauges reads the gauges; ctx ends the poll with the drain.
func pollDrainGauges(ctx context.Context, a adminClient) (drainGauges, error) {
	dump, err := a.get(ctx, "config_dump", url.Values{"resource": {"dynamic_listeners"}})
	if err != nil {
		return drainGauges{}, err
	}
	prefixes, err := listenerStatPrefixes(dump)
	if err != nil {
		return drainGauges{}, err
	}
	stats, err := a.get(ctx, "stats", url.Values{"format": {"json"}, "filter": {drainStatsFilter}})
	if err != nil {
		return drainGauges{}, err
	}
	return drainGaugesFrom(stats, prefixes)
}

type dumpedListener struct {
	Name       string `json:"name"`
	StatPrefix string `json:"stat_prefix"`
	Address    struct {
		SocketAddress *struct {
			Protocol  string `json:"protocol"`
			Address   string `json:"address"`
			PortValue uint32 `json:"port_value"`
		} `json:"socket_address"`
	} `json:"address"`
	InternalListener  json.RawMessage `json:"internal_listener"`
	UDPListenerConfig json.RawMessage `json:"udp_listener_config"`
}

type dumpedListenerState struct {
	Listener *dumpedListener `json:"listener"`
}

type listenersDump struct {
	Configs []struct {
		Type          string               `json:"@type"`
		Name          string               `json:"name"`
		ActiveState   *dumpedListenerState `json:"active_state"`
		DrainingState *dumpedListenerState `json:"draining_state"`
	} `json:"configs"`
}

// listenerStatPrefixes returns the listener stats scopes of the active and
// draining dynamic listeners in a /config_dump?resource=dynamic_listeners
// body. Generations of one address share a scope.
func listenerStatPrefixes(body []byte) (map[string]bool, error) {
	var d listenersDump
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, fmt.Errorf("parse listeners config dump: %w", err)
	}
	prefixes := make(map[string]bool)
	for _, c := range d.Configs {
		if c.Type != dynamicListenerType {
			return nil, fmt.Errorf("unexpected config dump entry %q", c.Type)
		}
		for _, st := range []*dumpedListenerState{c.ActiveState, c.DrainingState} {
			if st == nil {
				continue
			}
			if st.Listener == nil {
				return nil, fmt.Errorf("listener %q: state without listener", c.Name)
			}
			if sa := st.Listener.Address.SocketAddress; len(st.Listener.UDPListenerConfig) > 0 || (sa != nil && sa.Protocol == "UDP") {
				return nil, fmt.Errorf("listener %q: %w", c.Name, errUDPListener)
			}
			p, err := listenerStatScope(st.Listener)
			if err != nil {
				return nil, fmt.Errorf("listener %q: %w", c.Name, err)
			}
			prefixes[p] = true
		}
	}
	return prefixes, nil
}

// listenerStatScope names the listener stats scope as Envoy's
// listenerStatsScope does, with the ':' the stats sanitizer replaces.
func listenerStatScope(l *dumpedListener) (string, error) {
	if l.StatPrefix != "" {
		return escapeStatColons(l.StatPrefix), nil
	}
	if len(l.InternalListener) > 0 {
		return "envoy_internal_" + l.Name, nil
	}
	sa := l.Address.SocketAddress
	if sa == nil {
		return "", errors.New("listener without socket address")
	}
	ip, err := netip.ParseAddr(sa.Address)
	if err != nil {
		return "", fmt.Errorf("listener address: %w", err)
	}
	return escapeStatColons(netip.AddrPortFrom(ip, uint16(sa.PortValue)).String()), nil
}

func escapeStatColons(s string) string {
	return strings.ReplaceAll(s, ":", "_")
}

type statsBody struct {
	Stats []struct {
		Name  string          `json:"name"`
		Value json.RawMessage `json:"value"`
	} `json:"stats"`
}

const (
	listenerCxBit = 1 << iota
	listenerPreCxBit
	hcmRqActiveBit
	hcmRqTotalBit
	hcmCxBit
	hcmTxBufferedBit

	listenerAllBits = listenerCxBit | listenerPreCxBit
	hcmAllBits      = hcmRqActiveBit | hcmRqTotalBit | hcmCxBit | hcmTxBufferedBit
)

var listenerGauges = map[string]int{
	"downstream_cx_active":     listenerCxBit,
	"downstream_pre_cx_active": listenerPreCxBit,
}

var hcmGauges = map[string]int{
	"downstream_rq_active":            hcmRqActiveBit,
	"downstream_rq_total":             hcmRqTotalBit,
	"downstream_cx_active":            hcmCxBit,
	"downstream_cx_tx_bytes_buffered": hcmTxBufferedBit,
}

// drainGaugesFrom sums a /stats?format=json body filtered by drainStatsFilter.
// It fails when a gauge of an expected listener or of a seen HCM is missing.
func drainGaugesFrom(body []byte, listeners map[string]bool) (drainGauges, error) {
	var sb statsBody
	if err := json.Unmarshal(body, &sb); err != nil {
		return drainGauges{}, fmt.Errorf("parse stats: %w", err)
	}

	var g drainGauges
	// A dynamic listener with the readiness listener's scope is never skipped.
	skipReady := !listeners[readyListenerScope]
	listenerSeen := make(map[string]int)
	hcmSeen := make(map[string]int)
	for _, s := range sb.Stats {
		if s.Name == "" {
			continue
		}
		v, ok := statValue(s.Value)
		if !ok {
			continue
		}
		scope, gauge := splitStatName(s.Name)
		switch {
		case strings.HasPrefix(s.Name, "listener."):
			x := strings.TrimPrefix(scope, "listener.")
			bit, ok := listenerGauges[gauge]
			if !ok || x == "admin" || strings.HasPrefix(x, "admin.") || perThreadScope.MatchString(x) ||
				(skipReady && x == readyListenerScope) {
				continue
			}
			listenerSeen[x] |= bit
			if bit == listenerCxBit {
				g.ListenerCx += v
			} else {
				g.PreCx += v
			}
		case strings.HasPrefix(s.Name, "http."):
			p := strings.TrimPrefix(scope, "http.")
			bit, ok := hcmGauges[gauge]
			// user_agent scopes repeat rq_total under the HCM prefix.
			if !ok || p == "admin" || strings.Contains(p, ".user_agent.") || (skipReady && p == readyHCMScope) {
				continue
			}
			hcmSeen[p] |= bit
			switch bit {
			case hcmRqActiveBit:
				g.RqActive += v
			case hcmRqTotalBit:
				g.RqTotal += v
			case hcmCxBit:
				g.HCMCx += v
			case hcmTxBufferedBit:
				g.TxBuffered += v
			}
		case gauge == "downstream_cx_tx_bytes_buffered":
			// tcp_proxy and other network filters.
			g.TxBuffered += v
		}
	}

	if len(listeners) == 0 && len(hcmSeen) > 0 {
		return g, errors.New("no dynamic listeners while HTTP connection managers exist")
	}
	var missing []string
	for x := range listeners {
		if listenerSeen[x] != listenerAllBits {
			missing = append(missing, "listener."+x)
		}
	}
	for x, bits := range listenerSeen {
		if bits != listenerAllBits && !listeners[x] {
			missing = append(missing, "listener."+x)
		}
	}
	for p, bits := range hcmSeen {
		if bits != hcmAllBits {
			missing = append(missing, "http."+p)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return g, fmt.Errorf("incomplete gauges for %s", strings.Join(missing, ", "))
	}
	return g, nil
}

// splitStatName splits "a.b.c.gauge" into "a.b.c" and "gauge".
func splitStatName(name string) (string, string) {
	i := strings.LastIndexByte(name, '.')
	if i < 0 {
		return "", name
	}
	return name[:i], name[i+1:]
}

func statValue(raw json.RawMessage) (int64, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] == '"' {
		return 0, false
	}
	v, err := strconv.ParseInt(string(raw), 10, 64)
	return v, err == nil
}
