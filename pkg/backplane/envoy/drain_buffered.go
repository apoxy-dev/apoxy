//go:build !a4nobuffer

package envoy

// drainCheckTxBuffered keeps the idle exit waiting for unsent response bytes.
const drainCheckTxBuffered = true
