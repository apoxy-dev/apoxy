package vpc

import (
	"bytes"
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/agent"
)

// statusAgent is an agent for the admin API with a fixed status.
type statusAgent struct{ st agent.Status }

func (statusAgent) Attach(context.Context, agent.AttachmentSpec) (agent.Attachment, error) {
	return agent.Attachment{}, nil
}
func (statusAgent) Detach(context.Context, string) error { return nil }
func (statusAgent) Attachments() []agent.Attachment      { return nil }
func (statusAgent) Routes() []agent.Route                { return nil }
func (s statusAgent) Status() agent.Status               { return s.st }

// TestStatusCmd reads the direct paths of an agent through its admin API.
func TestStatusCmd(t *testing.T) {
	dir, err := os.MkdirTemp("", "vpc-status")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "admin.sock")
	st := agent.Status{Direct: []agent.DirectStatus{
		{
			Peer: "b", Key: "ab", Instance: "i-1", State: agent.DirectDirect,
			Prefixes: []netip.Prefix{netip.MustParsePrefix("fd00:1::/96"), netip.MustParsePrefix("fd00:2::/96")},
			Address:  netip.MustParseAddrPort("192.0.2.1:9000"), RTT: 1234 * time.Microsecond,
		},
		{Peer: "c", State: agent.DirectRelay, Reason: agent.ReasonProbeFailed},
		{State: agent.DirectOpening, Prefixes: []netip.Prefix{netip.MustParsePrefix("fd00:3::/96")}, Reason: agent.ReasonNoDirectPaths},
	}}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- agent.ServeAdmin(ctx, path, statusAgent{st}) }()
	t.Cleanup(func() {
		cancel()
		assert.NoError(t, <-served)
	})

	var out string
	require.Eventually(t, func() bool {
		var buf bytes.Buffer
		cmd := StatusCmd()
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)
		cmd.SetArgs([]string{"--admin-addr", path})
		if cmd.ExecuteContext(context.Background()) != nil {
			return false
		}
		out = buf.String()
		return true
	}, 5*time.Second, 20*time.Millisecond, "the command reads the admin API")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	require.Len(t, lines, 4, out)
	assert.Equal(t, []string{"PEER", "STATE", "ADDRESS", "RTT", "PREFIXES", "REASON"}, strings.Fields(lines[0]))
	assert.Equal(t, []string{"b", "direct", "192.0.2.1:9000", "1.2ms", "fd00:1::/96,fd00:2::/96", "-"}, strings.Fields(lines[1]))
	assert.Equal(t, []string{"c", "relay", "-", "-", "-", "probe", "failed"}, strings.Fields(lines[2]))
	assert.Equal(t, []string{"-", "opening", "-", "-", "fd00:3::/96", "peer", "has", "no", "direct", "paths"}, strings.Fields(lines[3]))

	// With no agent on the socket, the command fails.
	cmd := StatusCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--admin-addr", filepath.Join(dir, "none.sock")})
	assert.ErrorContains(t, cmd.ExecuteContext(context.Background()), "failed to read the admin API")
}
