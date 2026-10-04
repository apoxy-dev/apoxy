package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenlHeader(t *testing.T) {
	h := genlHeader{cmd: netdevCmdDevGet, version: 1}
	assert.Equal(t, []byte{1, 1, 0, 0}, h.Serialize())
	assert.Equal(t, len(h.Serialize()), h.Len())
}
