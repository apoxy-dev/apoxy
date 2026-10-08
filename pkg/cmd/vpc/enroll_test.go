package vpc

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/vpc/identity"
	"github.com/apoxy-dev/apoxy/pkg/vpc/vpctest"
)

// TestEnrollFlags runs the command with flags that it must refuse before it
// makes an API client. It must write no file.
func TestEnrollFlags(t *testing.T) {
	cases := []struct {
		name    string
		args    func(out string) []string
		wantErr string
	}{
		{name: "no name", args: func(out string) []string { return []string{"--out", out} }, wantErr: "set --name"},
		{name: "no out", args: func(string) []string { return []string{"--name", "fleet"} }, wantErr: "set --out"},
		{name: "name is not a DNS label", args: func(out string) []string { return []string{"--name", "Web_1", "--out", out} }, wantErr: "invalid --name"},
		{name: "two networks", args: func(out string) []string { return []string{"a", "b", "--name", "fleet", "--out", out} }, wantErr: "accepts at most 1 arg"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "fleet.json")
			cmd := EnrollCmd()
			var buf bytes.Buffer
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)
			cmd.SetArgs(tc.args(out))
			require.ErrorContains(t, cmd.Execute(), tc.wantErr)
			require.NoFileExists(t, out)
		})
	}
}

func TestEnrollSummary(t *testing.T) {
	ca, err := vpctest.NewCA()
	require.NoError(t, err)
	cases := []struct {
		name   string
		relays []identity.Relay
		want   string // The relay count in the line.
	}{
		{name: "one relay", relays: []identity.Relay{{ID: "r1", Addresses: []string{"192.0.2.1:6081"}}}, want: "1 relay"},
		{
			name:   "two relays",
			relays: []identity.Relay{{ID: "r1", Addresses: []string{"192.0.2.1:6081"}}, {ID: "r2", Addresses: []string{"192.0.2.2:6081"}}},
			want:   "2 relays",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cred, err := ca.Credential("project-a", "vpc-1", "fleet", time.Hour)
			require.NoError(t, err)
			require.NoError(t, cred.SetRelays(tc.relays, nil))

			got := enrollSummary(cred, "/etc/apoxy/fleet.json")
			require.Equal(t, "Wrote identity file /etc/apoxy/fleet.json: identity spiffe://project-a/vpc/vpc-1/agent/fleet, "+tc.want+
				", certificate expires at "+cred.Cert.NotAfter.UTC().Format(time.RFC3339)+".", got)
			der, err := x509.MarshalPKCS8PrivateKey(cred.Key)
			require.NoError(t, err)
			require.NotContains(t, got, "PRIVATE KEY")
			require.NotContains(t, got, base64.StdEncoding.EncodeToString(der)[:32])
		})
	}
}
