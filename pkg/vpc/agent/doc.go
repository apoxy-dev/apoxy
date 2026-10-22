// SPDX-License-Identifier: AGPL-3.0-only

// Package agent is the VPC agent. It keeps relay sessions on the agent socket,
// and all data goes through the relays: as PSP, or as QUIC data frames on the
// relay session in QUIC mode.
package agent
