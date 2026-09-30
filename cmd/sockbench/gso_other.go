//go:build !linux

package main

import "errors"

const maxGSOSegments = 64

func gsoControl(int) ([]byte, error) { return nil, errors.New("UDP GSO needs Linux") }
