// SPDX-License-Identifier: AGPL-3.0-only

package p2p

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testKeys = ProbeKeys{
	SID:      [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
	Dialer:   [32]byte{1},
	Listener: [32]byte{2},
}

func TestProbe(t *testing.T) {
	cases := []struct {
		name    string
		p       Probe
		size    int
		wantLen int
	}{
		{"request", Probe{SID: testKeys.SID, TxID: [12]byte{9}, Round: 2}, 1320, 1320},
		{"largest", Probe{SID: testKeys.SID, Round: 1}, 1452, 1452},
		{"reply IPv4", Probe{Reply: true, SID: testKeys.SID, Seen: netip.MustParseAddrPort("192.0.2.1:4500")}, 1320, 1320},
		{"reply IPv6", Probe{Reply: true, SID: testKeys.SID, Seen: netip.MustParseAddrPort("[2001:db8::1]:443")}, 200, 200},
		{"no padding", Probe{SID: testKeys.SID}, MinProbeLen, MinProbeLen},
		{"size too small", Probe{SID: testKeys.SID}, 10, MinProbeLen},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := AppendProbe([]byte("prefix"), tc.p, tc.size, &testKeys.Dialer)
			require.Equal(t, "prefix", string(b[:6]))
			b = b[6:]
			assert.Len(t, b, tc.wantLen)
			sid, ok := ProbeSID(b)
			assert.True(t, ok)
			assert.Equal(t, testKeys.SID, sid)
			got, err := OpenProbe(b, &testKeys.Dialer)
			require.NoError(t, err)
			assert.Equal(t, tc.p, got)
			_, err = OpenProbe(b, &testKeys.Listener)
			assert.ErrorIs(t, err, ErrProbe)
		})
	}
}

func TestOpenProbeErrors(t *testing.T) {
	good := AppendProbe(nil, Probe{SID: testKeys.SID}, 300, &testKeys.Dialer)
	edit := func(f func(b []byte) []byte) []byte { return f(append([]byte(nil), good...)) }
	cases := []struct {
		name string
		b    []byte
	}{
		{"padding changed", edit(func(b []byte) []byte { b[100] ^= 1; return b })},
		{"tag changed", edit(func(b []byte) []byte { b[len(b)-1] ^= 1; return b })},
		{"reply flag set", edit(func(b []byte) []byte { b[2] |= flagReply; return b })},
		{"cut short", good[:len(good)-1]},
		{"too short", good[:MinProbeLen-1]},
		{"not a probe", edit(func(b []byte) []byte { b[0] = 0x04; return b })},
		{"unknown version", edit(func(b []byte) []byte { b[1] = 2; return b })},
		{"empty", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := OpenProbe(tc.b, &testKeys.Dialer)
			assert.ErrorIs(t, err, ErrProbe)
		})
	}
}

// tlsPair returns the connection states of both ends of a TLS 1.3 connection.
func tlsPair(t *testing.T) (client, server tls.ConnectionState) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"x"}, NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	cc := tls.Client(c1, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	sc := tls.Server(c2, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	errc := make(chan error, 1)
	go func() { errc <- sc.Handshake() }()
	require.NoError(t, cc.Handshake())
	require.NoError(t, <-errc)
	return cc.ConnectionState(), sc.ConnectionState()
}

func TestNewProbeKeys(t *testing.T) {
	cs, ss := tlsPair(t)
	ck, err := NewProbeKeys(cs)
	require.NoError(t, err)
	sk, err := NewProbeKeys(ss)
	require.NoError(t, err)
	assert.Equal(t, ck, sk)
	assert.NotEqual(t, ck.Dialer, ck.Listener)
	assert.NotEqual(t, [8]byte{}, ck.SID)

	other, _ := tlsPair(t)
	ok, err := NewProbeKeys(other)
	require.NoError(t, err)
	assert.NotEqual(t, ck.SID, ok.SID)
}

func BenchmarkProbe(b *testing.B) {
	buf := make([]byte, 0, 1452)
	p := Probe{SID: testKeys.SID, Round: 1}
	b.ReportAllocs()
	for b.Loop() {
		buf = AppendProbe(buf[:0], p, 1452, &testKeys.Dialer)
		if _, err := OpenProbe(buf, &testKeys.Dialer); err != nil {
			b.Fatal(err)
		}
	}
}
