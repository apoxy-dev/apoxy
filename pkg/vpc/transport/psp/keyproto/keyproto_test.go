// SPDX-License-Identifier: AGPL-3.0-only

package keyproto

import (
	"bytes"
	"testing"
	"time"

	"github.com/apoxy-dev/softpsp/keys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

func TestRoundTrip(t *testing.T) {
	sas := []keys.SA{
		{SPI: 0x8000_0101, Key: bytes.Repeat([]byte{1}, 16), VNI: 7, ExpiresIn: 10 * time.Minute, Lane: 0},
		{SPI: 0x0000_0202, Key: bytes.Repeat([]byte{2}, 32), VNI: 7, ExpiresIn: time.Second, Lane: 15},
	}
	cases := []struct {
		name string
		req  keys.Request
	}{
		{"offer", keys.Request{Op: keys.OpOffer, SAs: sas}},
		{"rekey", keys.Request{Op: keys.OpRekey, SAs: sas[:1]}},
		{"revoke", keys.Request{Op: keys.OpRevoke, SPIs: []uint32{1, 2}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wire, err := proto.Marshal(ToProto(tc.req))
			require.NoError(t, err)
			var back dp.KeysRequest
			require.NoError(t, proto.Unmarshal(wire, &back))
			got, err := FromProto(&back)
			require.NoError(t, err)
			assert.Equal(t, tc.req, got)
		})
	}
}

func TestFromProtoErrors(t *testing.T) {
	cases := []struct {
		name string
		m    *dp.KeysRequest
	}{
		{"no op", &dp.KeysRequest{}},
		{"lane too large", rekeyOf(&dp.SA{Spi: 1, ExpiresIn: durationpb.New(time.Minute), Lane: keys.MaxLanes})},
		{"no expiry", rekeyOf(&dp.SA{Spi: 1})},
		{"bad expiry", rekeyOf(&dp.SA{Spi: 1, ExpiresIn: &durationpb.Duration{Seconds: 1, Nanos: -1}})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := FromProto(tc.m)
			assert.Error(t, err)
		})
	}
}

func rekeyOf(sa *dp.SA) *dp.KeysRequest {
	return &dp.KeysRequest{Op: &dp.KeysRequest_Rekey{Rekey: &dp.RekeySA{Sas: []*dp.SA{sa}}}}
}
