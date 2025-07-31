package kex

import (
	"encoding/base64"
	"errors"
	"time"
)

// Key is a 16-byte symmetric key used for encryption/decryption.
type Key [16]byte

func (k Key) MarshalJSON() ([]byte, error) {
	return []byte(`"` + base64.StdEncoding.EncodeToString(k[:]) + `"`), nil
}

func (k *Key) UnmarshalJSON(data []byte) error {
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return errors.New("invalid key format")
	}
	decoded, err := base64.StdEncoding.DecodeString(string(data[1 : len(data)-1]))
	if err != nil {
		return err
	}
	if len(decoded) != 16 {
		return errors.New("key must be 16 bytes long")
	}
	copy(k[:], decoded)
	return nil
}

type Keys struct {
	// Epoch is the epoch number for this set of keys.
	Epoch int `json:"epoch"`
	// Send is the key the client should use for sending packets (base64-encoded).
	Send Key `json:"send"`
	// Recv is the key the client should use for receiving packets (base64-encoded).
	Recv Key `json:"recv"`
	// ExpiresAt is the expiration time for the keys, when this is exceeded, the client
	// should issue a renew keys request.
	ExpiresAt time.Time `json:"expiresAt"`
}

type Route struct {
	// Prefix is the CIDR prefix for the route.
	Prefix string `json:"prefix"`
}

type DNS struct {
	// Servers is a list of nameservers to use.
	Servers []string `json:"servers,omitempty"`
	// SearchDomains is a list of search domains to use.
	SearchDomains []string `json:"searchDomains,omitempty"`
	// NDots is the number of dots in name to trigger absolute lookup.
	NDots *int `json:"ndots,omitempty"`
}

type ConnectRequest struct {
	// Address is the optional public address and port of the client.
	// If not provided, we'll use the remote address of the request.
	// This is useful for clients that are behind NAT.
	Address string `json:"address,omitempty"`
}

type ConnectResponse struct {
	// NetworkID is the identifier for the virtual network.
	NetworkID int `json:"networkId"`
	// Keys contains the symmetric keys for sending and receiving packets.
	Keys Keys `json:"keys"`
	// MTU is the maximum transmission unit for the virtual network.
	MTU int `json:"mtu"`
	// Addresses is a list of IPv6 addresses assigned to the virtual network.
	Addresses []string `json:"addresses"`
	// Routes is a list of routes to configure for the virtual network.
	Routes []Route `json:"routes"`
	// DNS contains DNS configuration for the virtual network.
	DNS *DNS `json:"dns,omitempty"`
}

type RenewKeysResponse struct {
	// Keys contains the symmetric keys for sending and receiving packets.
	Keys Keys `json:"keys"`
}
