//go:build !linux

package main

// xdpFeatures needs Linux.
func xdpFeatures(string) ([]string, uint32) { return nil, 0 }
