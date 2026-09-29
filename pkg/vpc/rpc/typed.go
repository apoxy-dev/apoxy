// SPDX-License-Identifier: AGPL-3.0-only

package rpc

import (
	"context"
	"io"

	"google.golang.org/protobuf/proto"
)

// Typed stream APIs for generated code. Req and Res are generated protobuf
// message types; *Req and *Res implement proto.Message.

// ServerStreamClient reads the responses of a server-streaming call.
type ServerStreamClient[Res any] interface {
	// Recv returns the next response, or io.EOF after the last one.
	Recv() (*Res, error)
}

// ClientStreamClient sends the requests of a client-streaming call.
type ClientStreamClient[Req, Res any] interface {
	Send(*Req) error
	// CloseAndRecv ends the requests and returns the response.
	CloseAndRecv() (*Res, error)
}

// BidiStreamClient is the calling side of a bidirectional call.
type BidiStreamClient[Req, Res any] interface {
	Send(*Req) error
	CloseSend() error
	// Recv returns the next response, or io.EOF after the last one.
	Recv() (*Res, error)
}

// ServerStreamServer sends the responses of a server-streaming call.
type ServerStreamServer[Res any] interface {
	Send(*Res) error
}

// ClientStreamServer reads the requests of a client-streaming call.
type ClientStreamServer[Req any] interface {
	// Recv returns the next request, or io.EOF after the last one.
	Recv() (*Req, error)
}

// BidiStreamServer is the called side of a bidirectional call.
type BidiStreamServer[Req, Res any] interface {
	// Recv returns the next request, or io.EOF after the last one.
	Recv() (*Req, error)
	Send(*Res) error
}

func msg[T any](m *T) proto.Message { return any(m).(proto.Message) }

type clientStream[Req, Res any] struct{ cs *ClientStream }

func (s clientStream[Req, Res]) Send(m *Req) error { return s.cs.SendMsg(msg(m)) }
func (s clientStream[Req, Res]) CloseSend() error  { return s.cs.CloseSend() }

func (s clientStream[Req, Res]) Recv() (*Res, error) {
	m := new(Res)
	if err := s.cs.RecvMsg(msg(m)); err != nil {
		return nil, err
	}
	return m, nil
}

func (s clientStream[Req, Res]) CloseAndRecv() (*Res, error) {
	_ = s.cs.CloseSend()
	m := new(Res)
	if err := s.cs.recvLast(msg(m)); err != nil {
		return nil, err
	}
	return m, nil
}

// OpenServerStream starts a server-streaming call with the request in.
func OpenServerStream[Res any](ctx context.Context, c Caller, method string, in proto.Message) (ServerStreamClient[Res], error) {
	cs, err := c.NewStream(ctx, method)
	if err != nil {
		return nil, err
	}
	if err := cs.SendMsg(in); err != nil && err != io.EOF {
		return nil, cs.end(err, StreamCanceled)
	}
	_ = cs.CloseSend()
	return clientStream[struct{}, Res]{cs}, nil
}

// OpenClientStream starts a client-streaming call.
func OpenClientStream[Req, Res any](ctx context.Context, c Caller, method string) (ClientStreamClient[Req, Res], error) {
	cs, err := c.NewStream(ctx, method)
	if err != nil {
		return nil, err
	}
	return clientStream[Req, Res]{cs}, nil
}

// OpenBidiStream starts a bidirectional call.
func OpenBidiStream[Req, Res any](ctx context.Context, c Caller, method string) (BidiStreamClient[Req, Res], error) {
	cs, err := c.NewStream(ctx, method)
	if err != nil {
		return nil, err
	}
	return clientStream[Req, Res]{cs}, nil
}

type serverStream[Req, Res any] struct{ s *ServerStream }

func (s serverStream[Req, Res]) Send(m *Res) error { return s.s.SendMsg(msg(m)) }

func (s serverStream[Req, Res]) Recv() (*Req, error) {
	m := new(Req)
	if err := s.s.RecvMsg(msg(m)); err != nil {
		return nil, err
	}
	return m, nil
}

func recvRequest(s *ServerStream, m proto.Message) error {
	if err := s.RecvMsg(m); err != nil {
		if err == io.EOF {
			return Errorf(InvalidArgument, "missing request message")
		}
		return err
	}
	return nil
}

// HandleUnary adds a unary handler to m.
func HandleUnary[Req, Res any](m *Mux, method string, h func(context.Context, *Req) (*Res, error)) {
	m.Handle(method, func(ctx context.Context, s *ServerStream) error {
		in := new(Req)
		if err := recvRequest(s, msg(in)); err != nil {
			return err
		}
		out, err := h(ctx, in)
		if err != nil {
			return err
		}
		return s.SendMsg(msg(out))
	})
}

// HandleServerStream adds a server-streaming handler to m.
func HandleServerStream[Req, Res any](m *Mux, method string, h func(context.Context, *Req, ServerStreamServer[Res]) error) {
	m.Handle(method, func(ctx context.Context, s *ServerStream) error {
		in := new(Req)
		if err := recvRequest(s, msg(in)); err != nil {
			return err
		}
		return h(ctx, in, serverStream[Req, Res]{s})
	})
}

// HandleClientStream adds a client-streaming handler to m.
func HandleClientStream[Req, Res any](m *Mux, method string, h func(context.Context, ClientStreamServer[Req]) (*Res, error)) {
	m.Handle(method, func(ctx context.Context, s *ServerStream) error {
		out, err := h(ctx, serverStream[Req, Res]{s})
		if err != nil {
			return err
		}
		return s.SendMsg(msg(out))
	})
}

// HandleBidiStream adds a bidirectional handler to m.
func HandleBidiStream[Req, Res any](m *Mux, method string, h func(context.Context, BidiStreamServer[Req, Res]) error) {
	m.Handle(method, func(ctx context.Context, s *ServerStream) error {
		return h(ctx, serverStream[Req, Res]{s})
	})
}
