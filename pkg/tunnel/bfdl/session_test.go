package bfdl

import (
	"testing"
	"time"
)

func TestSessionStateMachine(t *testing.T) {
	// Simulate client and server sessions establishing a connection.
	client := NewSession(1, DefaultDetectMult, DefaultTxInterval)
	server := NewSession(2, DefaultDetectMult, DefaultTxInterval)

	// Both start in Down state.
	if client.State() != StateDown {
		t.Fatalf("client initial state: got %v, want Down", client.State())
	}
	if server.State() != StateDown {
		t.Fatalf("server initial state: got %v, want Down", server.State())
	}

	// Client sends Down to server -> server transitions to Init.
	var clientPkt, resp Packet
	client.BuildTx(&clientPkt)
	server.ProcessRx(&clientPkt, &resp)
	if server.State() != StateInit {
		t.Fatalf("server after recv Down: got %v, want Init", server.State())
	}

	// Server responds with Init to client -> client transitions to Up.
	var resp2 Packet
	client.ProcessRx(&resp, &resp2)
	if client.State() != StateUp {
		t.Fatalf("client after recv Init: got %v, want Up", client.State())
	}

	// Client sends Up to server -> server transitions to Up.
	client.BuildTx(&clientPkt)
	server.ProcessRx(&clientPkt, &resp)
	if server.State() != StateUp {
		t.Fatalf("server after recv Up: got %v, want Up", server.State())
	}
}

func TestSessionExpired(t *testing.T) {
	s := NewSession(1, 3, 10*time.Millisecond) // Short interval for testing.

	// Not expired before any Rx.
	if s.Expired() {
		t.Fatal("should not be expired before first Rx")
	}

	// Simulate an Rx.
	var resp Packet
	s.ProcessRx(&Packet{Version: 1, State: StateDown, MyDiscr: 99, DetectMult: 3}, &resp)

	// Not expired immediately after Rx.
	if s.Expired() {
		t.Fatal("should not be expired immediately after Rx")
	}

	// Wait for detect time to elapse (3 * 10ms = 30ms).
	time.Sleep(50 * time.Millisecond)
	if !s.Expired() {
		t.Fatal("should be expired after detect time")
	}
}

func TestSessionOnStateChange(t *testing.T) {
	var transitions []struct{ old, new State }
	s := NewSession(1, DefaultDetectMult, DefaultTxInterval)
	s.SetOnStateChange(func(old, new State) {
		transitions = append(transitions, struct{ old, new State }{old, new})
	})

	// Receive Down -> transition to Init.
	var resp Packet
	s.ProcessRx(&Packet{Version: 1, State: StateDown, MyDiscr: 2, DetectMult: 3}, &resp)
	if len(transitions) != 1 || transitions[0].old != StateDown || transitions[0].new != StateInit {
		t.Fatalf("expected Down->Init transition, got %+v", transitions)
	}

	// Receive Up -> transition to Up.
	s.ProcessRx(&Packet{Version: 1, State: StateUp, MyDiscr: 2, DetectMult: 3}, &resp)
	if len(transitions) != 2 || transitions[1].old != StateInit || transitions[1].new != StateUp {
		t.Fatalf("expected Init->Up transition, got %+v", transitions)
	}
}
