//go:build !linux

package router

import "fmt"

func NewClientNetlinkRouter(_ ...Option) (Router, error) {
	return nil, fmt.Errorf("client netlink router is not supported on this platform")
}
