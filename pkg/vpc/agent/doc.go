// SPDX-License-Identifier: AGPL-3.0-only

// Package agent is the VPC agent. It keeps a relay session on the agent
// socket and runs peer sessions to other agents in its datagrams. Data goes
// as PSP, or as QUIC data frames on the relay session in QUIC mode.
package agent
