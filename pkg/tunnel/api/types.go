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

type ConnectRequest struct {
	// Agent is the name of the agent.
	Agent string `json:"agent"`
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
	Epoch uint32 `json:"epoch"`
	// Send is the key the agent should use for sending packets (base64-encoded).
	Send Key `json:"send"`
	// Recv is the key the agent should use for receiving packets (base64-encoded).
	Recv Key `json:"recv"`
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
