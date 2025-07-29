package kex

import "time"

type Keys struct {
	// Epoch is the epoch number for this set of keys.
	Epoch int `json:"epoch"`
	// Send is the key the client should use for sending packets (base64-encoded).
	Send string `json:"send"`
	// Recv is the key the client should use for receiving packets (base64-encoded).
	Recv string `json:"recv"`
	// ExpiresAt is the expiration time for the keys.
	ExpiresAt time.Time `json:"expiresAt"`
}

type Route struct {
	// Prefix is the CIDR prefix for the route.
	Prefix string `json:"prefix"`
}

type DNSConfig struct {
	// Servers is a list of nameservers to use.
	Servers []string `json:"servers,omitempty"`
	// SearchDomains is a list of search domains to use.
	SearchDomains []string `json:"searchDomains,omitempty"`
	// NDots is the number of dots in name to trigger absolute lookup.
	NDots *int `json:"ndots,omitempty"`
}

type ConnectResponse struct {
	// NetworkID is the identifier for the virtual network.
	NetworkID int `json:"networkId"`
	// Keys contains the symmetric keys for sending and receiving packets.
	Keys Keys `json:"keys"`
	// MTU is the maximum transmission unit for the tunnel.
	MTU int `json:"mtu"`
	// Addresses is a list of IPv6 addresses assigned to the tunnel.
	Addresses []string `json:"addresses"`
	// Routes is a list of routes to configure for the tunnel.
	Routes []Route `json:"routes,omitempty"`
	// DNSConfig contains DNS configuration for the tunnel.
	DNSConfig *DNSConfig `json:"dnsConfig,omitempty"`
}

type RenewKeysResponse struct {
	// Keys contains the symmetric keys for sending and receiving packets.
	Keys Keys `json:"keys"`
}
