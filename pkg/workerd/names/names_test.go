// SPDX-License-Identifier: AGPL-3.0-only

package names

import "testing"

const testUUID = "7ce458d7-e20c-443c-aeeb-dbc5663c1240"

func TestResidentNames(t *testing.T) {
	cases := []struct {
		name        string
		tenant      string
		wantID      string
		wantCluster string
		wantSocket  string
	}{
		{
			// The empty tenant MUST reproduce the pre-tenancy constants
			// byte-for-byte: these exact strings were hardcoded in
			// pkg/gateway/xds/translator/workerd.go and are dialed by every
			// already-deployed single-project topology.
			name:        "legacy single-project",
			tenant:      "",
			wantID:      "apoxy-workerd-resident",
			wantCluster: "apoxy-workerd-resident",
			wantSocket:  "/run/workerd-manager/state/apoxy-workerd-resident.in.sock",
		},
		{
			name:        "project tenant",
			tenant:      testUUID,
			wantID:      "apoxy-workerd-resident-" + testUUID,
			wantCluster: "apoxy-workerd-resident/" + testUUID,
			wantSocket:  "/run/workerd-manager/state/apoxy-workerd-resident-" + testUUID + ".in.sock",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := string(ResidentID(tc.tenant)); got != tc.wantID {
				t.Errorf("ResidentID(%q) = %q, want %q", tc.tenant, got, tc.wantID)
			}
			if got := ResidentClusterName(tc.tenant); got != tc.wantCluster {
				t.Errorf("ResidentClusterName(%q) = %q, want %q", tc.tenant, got, tc.wantCluster)
			}
			if got := ResidentSocketPath("", tc.tenant); got != tc.wantSocket {
				t.Errorf("ResidentSocketPath(\"\", %q) = %q, want %q", tc.tenant, got, tc.wantSocket)
			}
			if got := ResidentSocketPath(DefaultStateDir, tc.tenant); got != tc.wantSocket {
				t.Errorf("ResidentSocketPath(DefaultStateDir, %q) = %q, want %q", tc.tenant, got, tc.wantSocket)
			}
		})
	}
}

// TestResidentSocketPathSunPathBudget fails before a naming-scheme change can
// break bind(2): AF_UNIX sun_path is ~108 bytes (104 on some BSDs), and the
// socket path is a cross-process contract the translator emits blind.
func TestResidentSocketPathSunPathBudget(t *testing.T) {
	got := ResidentSocketPath("", testUUID)
	if len(got) != 94 {
		t.Errorf("UUID-tenant socket path is %d bytes, want the documented 94: %q", len(got), got)
	}
	if len(got) > 104 {
		t.Errorf("UUID-tenant socket path is %d bytes, over the 104-byte sun_path budget: %q", len(got), got)
	}
}

func TestValidateTenant(t *testing.T) {
	cases := []struct {
		name    string
		tenant  string
		wantErr bool
	}{
		{name: "empty is the single-project tenant", tenant: "", wantErr: false},
		{name: "canonical lowercase uuid", tenant: testUUID, wantErr: false},
		{name: "uppercase uuid is not canonical", tenant: "7CE458D7-E20C-443C-AEEB-DBC5663C1240", wantErr: true},
		{name: "non-hyphenated uuid is not canonical", tenant: "7ce458d7e20c443caeebdbc5663c1240", wantErr: true},
		{name: "urn form is not canonical", tenant: "urn:uuid:" + testUUID, wantErr: true},
		{name: "path traversal", tenant: "../../etc", wantErr: true},
		{name: "arbitrary name", tenant: "default", wantErr: true},
		{name: "slash in tenant", tenant: "a/b", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateTenant(tc.tenant)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateTenant(%q) error = %v, wantErr %v", tc.tenant, err, tc.wantErr)
			}
		})
	}
}
