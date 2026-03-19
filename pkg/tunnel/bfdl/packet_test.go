package bfdl

import (
	"testing"
)

func TestMarshalUnmarshal(t *testing.T) {
	pkt := &Packet{
		Version:       1,
		Diag:          0,
		State:         StateInit,
		Poll:          true,
		Final:         false,
		DetectMult:    3,
		MyDiscr:       0xdeadbeef,
		YourDiscr:     0xcafebabe,
		DesiredMinTx:  10_000_000,
		RequiredMinRx: 10_000_000,
	}

	buf := Marshal(pkt)
	if len(buf) != 24 {
		t.Fatalf("expected 24 bytes, got %d", len(buf))
	}

	got, err := Unmarshal(buf)
	if err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if got.Version != pkt.Version {
		t.Errorf("version: got %d, want %d", got.Version, pkt.Version)
	}
	if got.State != pkt.State {
		t.Errorf("state: got %v, want %v", got.State, pkt.State)
	}
	if got.Poll != pkt.Poll {
		t.Errorf("poll: got %v, want %v", got.Poll, pkt.Poll)
	}
	if got.Final != pkt.Final {
		t.Errorf("final: got %v, want %v", got.Final, pkt.Final)
	}
	if got.DetectMult != pkt.DetectMult {
		t.Errorf("detectMult: got %d, want %d", got.DetectMult, pkt.DetectMult)
	}
	if got.MyDiscr != pkt.MyDiscr {
		t.Errorf("myDiscr: got 0x%x, want 0x%x", got.MyDiscr, pkt.MyDiscr)
	}
	if got.YourDiscr != pkt.YourDiscr {
		t.Errorf("yourDiscr: got 0x%x, want 0x%x", got.YourDiscr, pkt.YourDiscr)
	}
	if got.DesiredMinTx != pkt.DesiredMinTx {
		t.Errorf("desiredMinTx: got %d, want %d", got.DesiredMinTx, pkt.DesiredMinTx)
	}
	if got.RequiredMinRx != pkt.RequiredMinRx {
		t.Errorf("requiredMinRx: got %d, want %d", got.RequiredMinRx, pkt.RequiredMinRx)
	}
}

func TestUnmarshalTooShort(t *testing.T) {
	_, err := Unmarshal([]byte{0x01, 0x02})
	if err == nil {
		t.Fatal("expected error for short packet")
	}
}

func TestUnmarshalBadVersion(t *testing.T) {
	buf := Marshal(&Packet{Version: 1, State: StateDown, DetectMult: 3})
	buf[0] = 0x00 // Set version to 0.
	_, err := Unmarshal(buf)
	if err == nil {
		t.Fatal("expected error for bad version")
	}
}

func TestStateString(t *testing.T) {
	tests := []struct {
		s    State
		want string
	}{
		{StateAdminDown, "AdminDown"},
		{StateDown, "Down"},
		{StateInit, "Init"},
		{StateUp, "Up"},
		{State(99), "Unknown(99)"},
	}
	for _, tt := range tests {
		if got := tt.s.String(); got != tt.want {
			t.Errorf("State(%d).String() = %q, want %q", tt.s, got, tt.want)
		}
	}
}
