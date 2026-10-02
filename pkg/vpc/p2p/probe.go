// SPDX-License-Identifier: AGPL-3.0-only

// Package p2p has the path probe of VPC agents. An agent sends probes on the UDP socket of
// its QUIC sessions, and the receiver sends back a reply of the same size.
package p2p

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
)

// TypeProbe is the first byte of a path probe.
const TypeProbe = 0x02

const (
	probeVersion = 1
	flagReply    = 1
	tagLen       = 16
	// Type, version, flags, a zero byte, SID, TxID, Round and Seen.
	hdrLen = 4 + 8 + 12 + 4 + 18
	// MinProbeLen is the length of a probe with no padding.
	MinProbeLen = hdrLen + tagLen
)

// ErrProbe is the error for a probe that is too short, has an unknown
// version or has a bad tag.
var ErrProbe = errors.New("p2p: bad path probe")

// Probe is a path probe or its reply.
type Probe struct {
	Reply bool
	SID   [8]byte  // From ProbeKeys.
	TxID  [12]byte // Random ID of one probe run.
	Round uint32
	Seen  netip.AddrPort // In a reply: the source address of the probe.
}

// ProbeKeys are the probe keys of one QUIC connection. Both ends get the same keys.
type ProbeKeys struct {
	SID [8]byte
	// Dialer tags the probes of the QUIC client, Listener the replies of the server.
	Dialer, Listener [32]byte
}

// NewProbeKeys gets the probe keys from the TLS exporter of a connection.
func NewProbeKeys(cs tls.ConnectionState) (ProbeKeys, error) {
	var k ProbeKeys
	for _, x := range []struct {
		label, context string
		out            []byte
	}{
		{"EXPORTER-apoxy-probe-id", "", k.SID[:]},
		{"EXPORTER-apoxy-probe", "dialer", k.Dialer[:]},
		{"EXPORTER-apoxy-probe", "listener", k.Listener[:]},
	} {
		b, err := cs.ExportKeyingMaterial(x.label, []byte(x.context), len(x.out))
		if err != nil {
			return ProbeKeys{}, fmt.Errorf("p2p: export probe keys: %w", err)
		}
		copy(x.out, b)
	}
	return k, nil
}

// AppendProbe appends p to b, with zero padding to size bytes and a tag made
// with key. A size below MinProbeLen means MinProbeLen.
func AppendProbe(b []byte, p Probe, size int, key *[32]byte) []byte {
	size = max(size, MinProbeLen)
	start := len(b)
	b = slices.Grow(b, size)[:start+size]
	out := b[start:]
	out[0], out[1], out[2], out[3] = TypeProbe, probeVersion, 0, 0
	if p.Reply {
		out[2] = flagReply
	}
	copy(out[4:12], p.SID[:])
	copy(out[12:24], p.TxID[:])
	binary.BigEndian.PutUint32(out[24:28], p.Round)
	a := p.Seen.Addr().As16()
	copy(out[28:44], a[:])
	binary.BigEndian.PutUint16(out[44:hdrLen], p.Seen.Port())
	clear(out[hdrLen : size-tagLen])
	tag(out[size-tagLen:], out[:size-tagLen], key)
	return b
}

// ProbeSID returns the SID of the probe in b. It does not check the tag.
func ProbeSID(b []byte) ([8]byte, bool) {
	if len(b) < MinProbeLen || b[0] != TypeProbe || b[1] != probeVersion {
		return [8]byte{}, false
	}
	return [8]byte(b[4:12]), true
}

// OpenProbe checks the tag of the probe in b with key and returns the probe.
func OpenProbe(b []byte, key *[32]byte) (Probe, error) {
	sid, ok := ProbeSID(b)
	if !ok {
		return Probe{}, ErrProbe
	}
	n := len(b) - tagLen
	var want [tagLen]byte
	tag(want[:], b[:n], key)
	if !hmac.Equal(want[:], b[n:]) {
		return Probe{}, ErrProbe
	}
	p := Probe{
		Reply: b[2]&flagReply != 0,
		SID:   sid,
		TxID:  [12]byte(b[12:24]),
		Round: binary.BigEndian.Uint32(b[24:28]),
	}
	if p.Reply {
		p.Seen = netip.AddrPortFrom(netip.AddrFrom16([16]byte(b[28:44])).Unmap(), binary.BigEndian.Uint16(b[44:hdrLen]))
	}
	return p, nil
}

// tag puts the first 16 B of HMAC-SHA256(key, msg) in dst.
func tag(dst, msg []byte, key *[32]byte) {
	m := hmac.New(sha256.New, key[:])
	m.Write(msg)
	var sum [sha256.Size]byte
	copy(dst, m.Sum(sum[:0]))
}
