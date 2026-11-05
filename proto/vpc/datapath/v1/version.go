// SPDX-License-Identifier: AGPL-3.0-only

package datapathv1

import "fmt"

// Protocol revisions. One number covers the Relay, Peer and Mesh services
// and the packet formats. README.md has the revision table and the change rules.
const (
	// Revision is the protocol revision of this build. Each change to the proto
	// files or to a packet format adds 1.
	Revision uint32 = 26
	// MinRevision is the oldest revision of the other side that this build
	// works with.
	MinRevision uint32 = 25
)

// CheckRevision returns an error when the revision of v is below least, the minimum of the other
// side. who names the side of v in the error. A nil v is revision 0.
func CheckRevision(who string, v *Version, least uint32) error {
	if got := v.GetRevision(); got < least {
		return fmt.Errorf("%s revision %d is below the minimum %d", who, got, least)
	}
	return nil
}

// LocalVersion returns the Version of this build. build is the build string
// of the binary.
func LocalVersion(build string) *Version {
	return &Version{Revision: Revision, MinRevision: MinRevision, Build: build}
}
