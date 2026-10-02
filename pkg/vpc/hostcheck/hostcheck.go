// SPDX-License-Identifier: AGPL-3.0-only

// Package hostcheck finds host settings that limit the rate of a VPC tunnel.
package hostcheck

// Warning is a host setting that limits the tunnel, and the command that fixes it.
type Warning struct {
	Problem string
	Fix     string
}
