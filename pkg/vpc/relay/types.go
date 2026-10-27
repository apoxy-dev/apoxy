// SPDX-License-Identifier: AGPL-3.0-only

package relay

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/apoxy-dev/apoxy/pkg/vpc/relay/dp"
	"github.com/apoxy-dev/apoxy/pkg/vpc/rpc"
	dpv1 "github.com/apoxy-dev/apoxy/proto/vpc/datapath/v1"
)

const (
	// MinPacketSize is the smallest QUIC InitialPacketSize of a relay connection. Before path MTU
	// discovery, quic-go takes a datagram up to InitialPacketSize - 37 B, and a data frame is
	// 1280 B + 5 B.
	MinPacketSize = 1322
	// MaxLaneSources is the most lane ports of a connection: lanes 1 to 3 of the data plane.
	MaxLaneSources = dpLanes - 1
	// maxEntryPrefixes is the most addresses and routes of one attachment.
	maxEntryPrefixes = 64
	// minBurst is the smallest meter burst in bytes.
	minBurst = 64 << 10
	// rebindOverlap is the time that the previous PSP address of a connection stays valid after a
	// newer probe moves it.
	rebindOverlap = 5 * time.Second
	// noRouteInterval is the minimum time between two NoRoute messages for one address.
	noRouteInterval = time.Second
	// DefaultTableWriteInterval is the table write interval of a Config with none.
	DefaultTableWriteInterval = 100 * time.Millisecond
)

// VPCKey is the key of a routing domain: one VPC of one project. The VPC name and the network ID
// are not part of it.
type VPCKey struct {
	Project string
	UID     string
}

// KeyOf returns the key of ref.
func KeyOf(ref *dpv1.VPCRef) (VPCKey, error) {
	if ref.GetProjectId() == "" || ref.GetVpcUid() == "" {
		return VPCKey{}, rpc.Errorf(rpc.InvalidArgument, "vpc needs project_id and vpc_uid")
	}
	return VPCKey{Project: ref.GetProjectId(), UID: ref.GetVpcUid()}, nil
}

// Network is the data of one VPC that the relay serves.
type Network struct {
	// ID is the 24-bit network ID, the VNI on the wire.
	ID uint32
	// Name is the name of the VPC network object. The stats of an attachment have it.
	Name             string
	MTU              uint32 // Zero means the default MTU.
	DNSServers       []string
	DNSSearchDomains []string
}

// PortTarget is a data plane on a UDP socket, which has its own port for PSP packets and probes.
// Agents get that port in Welcome.
type PortTarget interface {
	dp.Target
	DataPort() uint16
}

// LoadTarget is a data plane that places new sessions on its workers by their receive rates, as
// dp.Pipeline. The key engine gives it a sample at each tick.
type LoadTarget interface {
	dp.Target
	SampleLoad(now time.Time)
}

// Config is the configuration of a Router.
type Config struct {
	// Relay is the ID and the public addresses of this relay. Welcome and the slot Routes carry
	// it. The ID must not be empty.
	Relay *dpv1.RelayRef
	// Trust checks the agent certs.
	Trust Trust
	// Addresses gives the addresses of the attachments.
	Addresses Addresses
	// Target is the data plane. Its UDP port for PSP packets and probes is dp.PortData, or the
	// port of a PortTarget.
	Target dp.Target
	// LaneRate is the meter rate of each lane of a connection in bytes per second. Zero means no
	// limit.
	LaneRate float64
	// LaneBurst is the lane meter burst in bytes. Zero means 100 ms of LaneRate. It is at least
	// 64 KiB.
	LaneBurst int
	// TunnelRate limits all data from one agent connection in bytes per second: the port meter.
	// Zero means no limit.
	TunnelRate float64
	// TunnelBurst is the burst of the port meter in bytes. Zero means 100 ms of TunnelRate. It is
	// at least 64 KiB.
	TunnelBurst int
	// LaneSources limits the lane ports of a connection, 0 to MaxLaneSources.
	LaneSources int
	// Busy gives the busy time of each thread of the data plane for the busy metric, as
	// dp.Device.Busy. nil: no busy metric.
	Busy func() []dp.ThreadBusy
	// TableWriteInterval is the shortest time between two table writes. The root writes the table
	// changes of this time in one batch. nil means DefaultTableWriteInterval; 0 writes each change
	// at once.
	TableWriteInterval *time.Duration
}

// Attachment is one attachment of an agent connection.
type Attachment struct {
	ID        string
	VPC       VPCKey
	NetworkID uint32
	// Network is the name of the VPC network object.
	Network string
	Name    string
	Labels  map[string]string
	// Subject is the SPIFFE ID of the agent.
	Subject string
	// Routes are the advertised prefixes that the relay accepted. The relay sets them after
	// Addresses.Assign.
	Routes []netip.Prefix
	// Addresses are the prefixes from Addresses.Assign.
	Addresses []netip.Prefix
	// Rank is the order that the agent gives to this connection among its connections to relays.
	// The lower one is selected first.
	Rank uint32
}

// prefixes returns the addresses and the routes of a, masked.
func (a *Attachment) prefixes() []netip.Prefix {
	out := make([]netip.Prefix, 0, len(a.Addresses)+len(a.Routes))
	for _, p := range a.Addresses {
		out = append(out, p.Masked())
	}
	for _, p := range a.Routes {
		out = append(out, p.Masked())
	}
	return out
}

// Addresses assigns overlay addresses to attachments. The relay host implements it. The relay
// calls it from one hook task at a time.
type Addresses interface {
	// Assign returns the prefixes of a new attachment, which has no Routes yet. It calls onLost
	// when their lease ends, also before it returns. onLost returns after the connection of the
	// attachment stopped its data. ctx ends when the connection closes.
	Assign(ctx context.Context, a *Attachment, onLost func()) ([]netip.Prefix, error)
	// Attached tells the host that the attach of a is complete. It must not block.
	Attached(a *Attachment)
	// Release frees the prefixes of an attachment that ended.
	Release(a *Attachment)
}

// OverlayAddr returns the address that an agent uses in a prefix from Addresses.Assign: the first
// address after the base.
func OverlayAddr(p netip.Prefix) netip.Addr {
	return p.Addr().Next()
}

// ValidateAttachment checks the name and the labels of an attachment.
func ValidateAttachment(name string, labels map[string]string) error {
	if errs := validation.IsDNS1123Subdomain(name); len(errs) > 0 {
		return fmt.Errorf("name %q: %s", name, strings.Join(errs, "; "))
	}
	for k, v := range labels {
		errs := append(validation.IsQualifiedName(k), validation.IsValidLabelValue(v)...)
		if len(errs) > 0 {
			return fmt.Errorf("label %q: %s", k, strings.Join(errs, "; "))
		}
	}
	return nil
}

// AttachmentStats is the identity and the counters of one attachment. The counters start at zero
// at the attach and do not decrease.
type AttachmentStats struct {
	// ID is the attachment ID. The Tunnel of the attachment has it as its name.
	ID string
	// Instance is the attach order number in the router.
	Instance uint64
	VPC      VPCKey
	// Network is the name of the VPC network object.
	Network string
	// Name is the name that the agent gave.
	Name string
	// Build is the build of the agent, from Hello.
	Build string
	// Since is the time of the attach.
	Since time.Time
	// RTT is the smoothed round-trip time of the connection. Zero is no sample.
	RTT time.Duration

	// RXPackets and RXBytes count the inner packets from the agent that the relay took. The
	// oldest attachment of a connection has all of them.
	RXPackets, RXBytes uint64
	// RXDrops counts the packets from the agent that the relay dropped. The data plane counts
	// drops by reason only, so it is zero.
	RXDrops uint64
	// TXPackets and TXBytes count the inner packets that the relay sent to the addresses and the
	// routes of the attachment.
	TXPackets, TXBytes uint64
}

// dataPort returns the UDP port of the data plane t for PSP packets and probes.
func dataPort(t dp.Target) uint16 {
	if pt, ok := t.(PortTarget); ok {
		return pt.DataPort()
	}
	return dp.PortData
}
