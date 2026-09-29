// SPDX-License-Identifier: AGPL-3.0-only

// Package rpc runs protobuf calls on the bidirectional streams of one QUIC
// connection. Each call uses one stream, and either side of the connection
// can start a call. QUIC gives multiplexing, flow control and cancel.
//
// Stream format (the side that opens the stream is the caller):
//
//	caller -> called: [type 0x01][ver 0x01] frame(header) frame(message)* FIN
//	called -> caller: frame(message)* frame(status) FIN
//	frame:            [kind 1 B][length uvarint, max 5 B][protobuf]
//	kinds:            0x01 CallHeader, 0x02 message, 0x03 Status
//
// A cancel sends RESET_STREAM and STOP_SENDING with a Stream* error code.
// The called side resets a stream with an unknown type or version with
// StreamUnsupported and a stream that is not valid with StreamProtocolError.
//
// protoc-gen-go-vpcrpc generates typed clients and servers for this package.
package rpc
