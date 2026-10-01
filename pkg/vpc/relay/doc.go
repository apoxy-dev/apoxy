// SPDX-License-Identifier: AGPL-3.0-only

// Package relay is the relay core of VPC Tunnels v2. Router keeps one
// routing domain for each VPC, keyed on the project and the VPC UID, and the
// SPI rows that forward PSP packets between agents without decryption.
//
// A relay session opens only for an agent cert that passes a local check
// with the Trust data: the chain goes to the agent CA, the SAN is an agent
// ID, and the agent is not revoked in its VPC. Each call must name the VPC
// in the cert.
//
// A sender registers each SPI over its authenticated relay session. The
// relay maps an outer source address to a sender only from that session,
// never from data. Rows end at UnregisterSPI, at expiry, after 5 minutes
// with no traffic, when either session closes, and when Permit stops
// allowing them.
package relay
