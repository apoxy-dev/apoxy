// SPDX-License-Identifier: AGPL-3.0-only

//go:build race

package psp

// testData is the size of the TCP test transfer. gVisor TCP is slow in race
// builds.
const testData = 32 << 10
