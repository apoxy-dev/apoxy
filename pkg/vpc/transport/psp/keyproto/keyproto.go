// SPDX-License-Identifier: AGPL-3.0-only

// Package keyproto converts SoftPSP key changes to and from the datapath
// messages of the peer session and the relay session.
package keyproto

import (
	"errors"
	"fmt"
	"slices"

	"github.com/apoxy-dev/softpsp/keys"
	"google.golang.org/protobuf/types/known/durationpb"

	dp "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

// ToProto returns req as the message of the Keys and Rekey calls.
func ToProto(req keys.Request) *dp.KeysRequest {
	switch req.Op {
	case keys.OpOffer:
		return &dp.KeysRequest{Op: &dp.KeysRequest_Offer{Offer: &dp.OfferSAs{Sas: sasToProto(req.SAs)}}}
	case keys.OpRekey:
		return &dp.KeysRequest{Op: &dp.KeysRequest_Rekey{Rekey: &dp.RekeySA{Sas: sasToProto(req.SAs)}}}
	case keys.OpRevoke:
		return &dp.KeysRequest{Op: &dp.KeysRequest_Revoke{Revoke: &dp.RevokeSA{Spis: slices.Clone(req.SPIs)}}}
	}
	return &dp.KeysRequest{}
}

// FromProto returns the key change in m.
func FromProto(m *dp.KeysRequest) (keys.Request, error) {
	switch op := m.GetOp().(type) {
	case *dp.KeysRequest_Offer:
		sas, err := sasFromProto(op.Offer.GetSas())
		return keys.Request{Op: keys.OpOffer, SAs: sas}, err
	case *dp.KeysRequest_Rekey:
		sas, err := sasFromProto(op.Rekey.GetSas())
		return keys.Request{Op: keys.OpRekey, SAs: sas}, err
	case *dp.KeysRequest_Revoke:
		return keys.Request{Op: keys.OpRevoke, SPIs: slices.Clone(op.Revoke.GetSpis())}, nil
	}
	return keys.Request{}, errors.New("keyproto: keys request has no op")
}

func sasToProto(sas []keys.SA) []*dp.SA {
	out := make([]*dp.SA, len(sas))
	for i, sa := range sas {
		out[i] = &dp.SA{
			Spi:       sa.SPI,
			Key:       slices.Clone(sa.Key),
			Vni:       sa.VNI,
			ExpiresIn: durationpb.New(sa.ExpiresIn),
			Lane:      uint32(sa.Lane),
		}
	}
	return out
}

func sasFromProto(sas []*dp.SA) ([]keys.SA, error) {
	out := make([]keys.SA, len(sas))
	for i, sa := range sas {
		if err := sa.GetExpiresIn().CheckValid(); err != nil {
			return nil, fmt.Errorf("keyproto: SA %#x: expires_in: %w", sa.GetSpi(), err)
		}
		if sa.GetLane() >= keys.MaxLanes {
			return nil, fmt.Errorf("keyproto: SA %#x: lane %d is not below %d", sa.GetSpi(), sa.GetLane(), keys.MaxLanes)
		}
		out[i] = keys.SA{
			SPI:       sa.GetSpi(),
			Key:       slices.Clone(sa.GetKey()),
			VNI:       sa.GetVni(),
			ExpiresIn: sa.GetExpiresIn().AsDuration(),
			Lane:      int(sa.GetLane()),
		}
	}
	return out, nil
}
