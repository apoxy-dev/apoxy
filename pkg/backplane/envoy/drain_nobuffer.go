//go:build a4nobuffer

package envoy

// drainCheckTxBuffered is off only in the E7b control build. Never ship it.
const drainCheckTxBuffered = false
