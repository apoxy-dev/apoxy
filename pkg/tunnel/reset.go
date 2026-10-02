package tunnel

import (
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/quic-go/quic-go"
)

// statelessResetKey derives the QUIC stateless reset key of a server from
// secret, its role and its name. Servers that share secret need different names.
func statelessResetKey(secret []byte, role, name string) (*quic.StatelessResetKey, error) {
	if len(secret) == 0 {
		return nil, errors.New("stateless reset secret is empty")
	}
	k, err := hkdf.Key(sha256.New, secret, nil, "apoxy "+role+" quic stateless reset "+name, len(quic.StatelessResetKey{}))
	if err != nil {
		return nil, fmt.Errorf("failed to derive the stateless reset key: %w", err)
	}
	key := quic.StatelessResetKey(k)
	return &key, nil
}
