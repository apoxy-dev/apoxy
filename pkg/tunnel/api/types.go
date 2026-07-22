package api

import (
	"encoding/base64"
	"errors"
	"time"
)

type Request struct {
	// Agent is the name of the agent.
	Agent string `json:"agent"`
	// ID is the unique ID of the connection.
	ID string `json:"id"`
}

// TunnelPathMTU is the assumed underlay path MTU between an agent and a relay.
// Both sides derive the inner tunnel MTU from it via icx.MTU(TunnelPathMTU),
// which subtracts the IPv6+UDP+Geneve+AES encapsulation overhead. It must stay
// large enough that the derived inner MTU is at least the IPv6 minimum link MTU
// (1280): the overlay is IPv6 ULA, and Linux refuses to run IPv6 on a device
// below 1280. icx.MTU(1500) = 1392, comfortably above that floor.
const TunnelPathMTU = 1500

type ConnectRequest struct {
	// Agent is the name of the agent.
	Agent string `json:"agent"`
	// MetricsPort is the port the agent's Prometheus metrics server listens on.
	// 0 means the agent does not expose metrics.
	MetricsPort int `json:"metricsPort,omitempty"`
	// Labels are agent-declared labels used for service selection. The relay
	// rejects labels outside the credential's allowed label sets.
	Labels map[string]string `json:"labels,omitempty"`
	// AdvertisedRoutes are CIDRs reachable behind this connection. The relay
	// rejects routes outside the credential's allowed CIDRs.
	AdvertisedRoutes []string `json:"advertisedRoutes,omitempty"`
	// AgentInstance is a stable per-process UUID identifying the agent instance.
	AgentInstance string `json:"agentInstance,omitempty"`
}

type ConnectResponse struct {
	// ID is the unique ID of the connection.
	ID string `json:"id"`
	// VNI is the virtual network identifier assigned to the connection.
	VNI uint `json:"vni"`
	// MTU is the maximum transmission unit for the connection.
	MTU int `json:"mtu"`
	// Keys contains the symmetric keys for sending and receiving packets.
	Keys Keys `json:"keys"`
	// Addresses is a list of overlay addresses assigned to the connection.
	Addresses []string `json:"addresses"`
	// Routes is a list of routes to configure for the connection.
	Routes []Route `json:"routes,omitempty"`
	// DNS contains DNS configuration for the connection.
	DNS *DNS `json:"dns,omitempty"`
	// RelayAddresses is a list of alternate relay addresses that are serving the
	// same tunnel. This can be used for establishing redundant routes.
	RelayAddresses []string `json:"relayAddresses,omitempty"`
}

type UpdateKeysResponse struct {
	// Keys contains the symmetric keys for sending and receiving packets.
	Keys Keys `json:"keys"`
}

// MasterSecret is the 32-byte PSP master secret a connection's per-epoch
// AES-GCM data keys derive from. The icx handler performs the derivation on
// each side (psp.DeriveSAKey over the epoch's role-partitioned SPIs), so no
// finished data key ever crosses the wire or the handler API boundary.
type MasterSecret [32]byte

func (m MasterSecret) MarshalJSON() ([]byte, error) {
	return []byte(`"` + base64.StdEncoding.EncodeToString(m[:]) + `"`), nil
}

func (m *MasterSecret) UnmarshalJSON(data []byte) error {
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return errors.New("invalid master secret format")
	}
	decoded, err := base64.StdEncoding.DecodeString(string(data[1 : len(data)-1]))
	if err != nil {
		return err
	}
	if len(decoded) != 32 {
		return errors.New("master secret must be 32 bytes long")
	}
	copy(m[:], decoded)
	return nil
}

type Keys struct {
	// Epoch is the key generation for this connection; it starts at 1 and
	// strictly increases on every rotation. Each side maps it onto mirrored
	// per-direction SPIs (psp.EpochSPIs: relay = Responder, agent = Initiator)
	// and the handler derives that epoch's keys from the master secret.
	Epoch uint32 `json:"epoch"`
	// MasterSecret is the connection's PSP master secret (base64-encoded). It is
	// minted once per connection; rotations advance Epoch under the same master.
	MasterSecret MasterSecret `json:"masterSecret"`
	// ExpiresAt is the expiration time for the keys, when this is exceeded, the agent
	// should issue an update keys request.
	ExpiresAt time.Time `json:"expiresAt"`
}

type Route struct {
	// Destination is the destination CIDR for the route.
	Destination string `json:"destination"`
}

type DNS struct {
	// Servers is a list of nameservers to use.
	Servers []string `json:"servers,omitempty"`
	// SearchDomains is a list of search domains to use.
	SearchDomains []string `json:"searchDomains,omitempty"`
	// NDots is the number of dots in name to trigger absolute lookup.
	NDots *int `json:"ndots,omitempty"`
}
