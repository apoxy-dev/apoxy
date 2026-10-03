// SPDX-License-Identifier: AGPL-3.0-only

package vpctest

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"

	"github.com/apoxy-dev/apoxy/pkg/vpc/relay"
)

// Networks is a relay.Networks with one VPC.
type Networks struct {
	Project, VPC string
	Net          relay.Network
}

var _ relay.Networks = Networks{}

// Network returns Net, or an error for other VPCs.
func (n Networks) Network(project, uid string) (relay.Network, error) {
	if project != n.Project || uid != n.VPC {
		return relay.Network{}, fmt.Errorf("unknown VPC %s/%s", project, uid)
	}
	return n.Net, nil
}

// Addresses is a relay.Addresses that gives each attachment the next /96 in
// the VPC network fd61:706f:7879:12:3400::/72, and counts the live
// attachments of each agent.
type Addresses struct {
	mu      sync.Mutex
	next    int
	live    map[string]int // Subject to live attachments.
	maxLive map[string]int
}

var _ relay.Addresses = (*Addresses)(nil)

func (a *Addresses) Assign(_ context.Context, att *relay.Attachment, _ func()) ([]netip.Prefix, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.next >= 0xffff {
		return nil, errors.New("address pool is full")
	}
	a.next++
	if a.live == nil {
		a.live, a.maxLive = map[string]int{}, map[string]int{}
	}
	a.live[att.Subject]++
	a.maxLive[att.Subject] = max(a.maxLive[att.Subject], a.live[att.Subject])
	return []netip.Prefix{netip.MustParsePrefix(fmt.Sprintf("fd61:706f:7879:12:3400:%x::/96", a.next))}, nil
}

func (a *Addresses) Release(att *relay.Attachment) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.live[att.Subject]--
}

// Overlap returns the most attachments of subject that were live at once.
func (a *Addresses) Overlap(subject string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.maxLive[subject]
}

// LiveOf returns the live attachments of subject.
func (a *Addresses) LiveOf(subject string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.live[subject]
}
