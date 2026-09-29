// SPDX-License-Identifier: AGPL-3.0-only

package rpc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/quic-go/quic-go"
)

// Code is a call status code. The numbers are the same as the gRPC codes.
type Code uint32

const (
	OK                 Code = 0
	Canceled           Code = 1
	Unknown            Code = 2
	InvalidArgument    Code = 3
	DeadlineExceeded   Code = 4
	NotFound           Code = 5
	AlreadyExists      Code = 6
	PermissionDenied   Code = 7
	ResourceExhausted  Code = 8
	FailedPrecondition Code = 9
	Aborted            Code = 10
	OutOfRange         Code = 11
	Unimplemented      Code = 12
	Internal           Code = 13
	Unavailable        Code = 14
	DataLoss           Code = 15
	Unauthenticated    Code = 16
)

var codeNames = [...]string{
	"OK", "Canceled", "Unknown", "InvalidArgument", "DeadlineExceeded", "NotFound",
	"AlreadyExists", "PermissionDenied", "ResourceExhausted", "FailedPrecondition",
	"Aborted", "OutOfRange", "Unimplemented", "Internal", "Unavailable", "DataLoss",
	"Unauthenticated",
}

func (c Code) String() string {
	if int(c) < len(codeNames) {
		return codeNames[c]
	}
	return "Code(" + strconv.FormatUint(uint64(c), 10) + ")"
}

// QUIC stream error codes that this package sends in RESET_STREAM and STOP_SENDING.
const (
	// StreamNoError tells the peer that the call is complete and more data is not necessary.
	StreamNoError quic.StreamErrorCode = 0x0
	// StreamCanceled tells the peer that the call was canceled.
	StreamCanceled quic.StreamErrorCode = 0x1
	// StreamDeadlineExceeded tells the peer that the call deadline expired.
	StreamDeadlineExceeded quic.StreamErrorCode = 0x2
	// StreamProtocolError tells the peer that its stream data is not valid.
	StreamProtocolError quic.StreamErrorCode = 0x3
	// StreamUnsupported tells the peer that the stream type or version is not supported.
	StreamUnsupported quic.StreamErrorCode = 0x4
)

// Error is a call error with a status code.
type Error struct {
	Code    Code
	Message string
	cause   error
}

func (e *Error) Error() string {
	return "rpc error: code = " + e.Code.String() + " desc = " + e.Message
}

// Unwrap returns the local error that caused e, if any.
func (e *Error) Unwrap() error { return e.cause }

// Errorf returns an *Error with code c. A %w verb sets the cause.
func Errorf(c Code, format string, a ...any) error {
	err := fmt.Errorf(format, a...)
	return &Error{Code: c, Message: err.Error(), cause: errors.Unwrap(err)}
}

// CodeOf returns the status code of err.
func CodeOf(err error) Code {
	if err == nil {
		return OK
	}
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	switch {
	case errors.Is(err, context.Canceled):
		return Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return DeadlineExceeded
	}
	return Unknown
}

// toStatus converts err to the code and message to send to the caller.
func toStatus(err error) (Code, string) {
	if err == nil {
		return OK, ""
	}
	var e *Error
	if errors.As(err, &e) {
		return e.Code, e.Message
	}
	return CodeOf(err), err.Error()
}

// ctxError returns the error for a call whose context ended.
func ctxError(ctx context.Context) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return &Error{Code: DeadlineExceeded, Message: "deadline exceeded", cause: context.Cause(ctx)}
	}
	return &Error{Code: Canceled, Message: "call canceled", cause: context.Cause(ctx)}
}

// ctxStreamCode returns the stream error code for a call whose context ended.
func ctxStreamCode(ctx context.Context) quic.StreamErrorCode {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return StreamDeadlineExceeded
	}
	return StreamCanceled
}

// transportError converts an error from a QUIC stream or connection to an *Error.
func transportError(err error) error {
	var se *quic.StreamError
	if errors.As(err, &se) && se.Remote {
		c := Unknown
		switch se.ErrorCode {
		case StreamCanceled:
			c = Canceled
		case StreamDeadlineExceeded:
			c = DeadlineExceeded
		case StreamProtocolError:
			c = Internal
		case StreamUnsupported:
			c = Unimplemented
		}
		return &Error{Code: c, Message: "stream reset by peer", cause: err}
	}
	var fe *frameError
	switch {
	case errors.Is(err, errFrameTooLarge):
		return &Error{Code: ResourceExhausted, Message: err.Error(), cause: err}
	case errors.As(err, &fe), errors.Is(err, io.ErrUnexpectedEOF):
		return &Error{Code: Internal, Message: err.Error(), cause: err}
	}
	return &Error{Code: Unavailable, Message: err.Error(), cause: err}
}
