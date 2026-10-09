// SPDX-License-Identifier: AGPL-3.0-only

package datapathv1

// Protocol revisions. One number covers the Relay, Peer and Mesh services and
// the packet formats. README.md has the revision table and the change rules.
const (
	// Revision is the protocol revision of this build. Each change to the proto
	// files or to a packet format adds 1.
	Revision uint32 = 14
	// MinRevision is the oldest revision of the other side that this build
	// works with.
	MinRevision uint32 = 0
)

// LocalVersion returns the Version of this build. build is the build string
// of the binary.
func LocalVersion(build string) *Version {
	return &Version{Revision: Revision, MinRevision: MinRevision, Build: build}
}
