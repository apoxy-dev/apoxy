// SPDX-License-Identifier: AGPL-3.0-only

// Package relay is the relay core of VPC Tunnels v2. Router keeps one
// routing domain for each VPC, keyed on the project and the VPC UID, and the
// SPI rows that forward PSP packets between agents without decryption.
//
// A sender registers each SPI over its authenticated relay session. The
// relay maps an outer source address to a sender only from that session,
// never from data. Rows end at UnregisterSPI, at expiry, after 5 minutes
// with no traffic, when either session closes, and when Permit stops
// allowing them.
package relay
