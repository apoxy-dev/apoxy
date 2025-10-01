//go:build !linux

package router

import (
	"context"
	"errors"
	"net/netip"

	"github.com/apoxy-dev/apoxy/pkg/tunnel/connection"
)

func NewICXNetlinkRouter(_ ...Option) (Router, error) {
	return &notImplementedRouter{}, nil
}

type notImplementedRouter struct{}

func (r *notImplementedRouter) Start(ctx context.Context) error {
	return errors.New("not implemented")
}

func (r *notImplementedRouter) AddAddr(_ netip.Prefix, _ connection.Connection) error {
	return errors.New("not implemented")
}

func (r *notImplementedRouter) DelAddr(_ netip.Prefix) error {
	return errors.New("not implemented")
}

func (r *notImplementedRouter) AddRoute(dst netip.Prefix) error {
	return errors.New("not implemented")
}

func (r *notImplementedRouter) DelRoute(dst netip.Prefix) error {
	return errors.New("not implemented")
}

func (r *notImplementedRouter) Close() error {
	return nil
}
