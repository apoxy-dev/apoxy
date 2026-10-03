// SPDX-License-Identifier: AGPL-3.0-only

//go:build !linux

package main

import "syscall"

func sockRcvbuf(syscall.Conn) int64 { return -1 }

func sockDrops(syscall.Conn) int64 { return -1 }
