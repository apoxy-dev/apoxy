// SPDX-License-Identifier: AGPL-3.0-only

package proc

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMailbox(t *testing.T) {
	cases := []struct {
		name string
		max  int
		run  func(t *testing.T, m *Mailbox)
	}{
		{name: "order", run: func(t *testing.T, m *Mailbox) {
			for _, e := range []int{1, 2, 3} {
				require.True(t, m.Send(e))
			}
			assert.Equal(t, []any{1, 2, 3}, m.Take())
			assert.Empty(t, m.Take())
		}},
		{name: "limit", max: 2, run: func(t *testing.T, m *Mailbox) {
			assert.True(t, m.Send(1))
			assert.True(t, m.Send(2))
			assert.False(t, m.Send(3), "send to a full mailbox")
			assert.Equal(t, []any{1, 2}, m.Take())
			assert.True(t, m.Send(4), "send after a take")
			assert.Equal(t, []any{4}, m.Take())
		}},
		{name: "close returns the events not taken", run: func(t *testing.T, m *Mailbox) {
			require.True(t, m.Send(1))
			require.True(t, m.Send(2))
			assert.Equal(t, []any{1, 2}, m.Close())
			assert.False(t, m.Send(3), "send after close")
			assert.Empty(t, m.Take())
			assert.Empty(t, m.Close())
		}},
		{name: "wake after a send", run: func(t *testing.T, m *Mailbox) {
			select {
			case <-m.Wake():
				t.Fatal("wake with no send")
			default:
			}
			require.True(t, m.Send(1))
			require.True(t, m.Send(2))
			select {
			case <-m.Wake():
			default:
				t.Fatal("no wake after a send")
			}
			assert.Equal(t, []any{1, 2}, m.Take())
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { tc.run(t, NewMailbox(tc.max)) })
	}
}

func TestValues(t *testing.T) {
	type a struct{ n int }
	type b struct{ n int }
	var m Values
	p := &a{1}
	Store(&m, "a", p)
	assert.Same(t, p, Load[*a](&m, "a"))
	assert.Nil(t, Load[*b](&m, "a"), "load of another type")
	assert.Nil(t, Load[*a](&m, "none"), "load of a key that is not there")
	v, _ := m.Load("a")
	assert.Same(t, p, As[*a](v))
	assert.Nil(t, As[*b](v), "As of another type")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	Store(&m, "b", &b{2})
	got := make(chan []string, 16)
	Watch(ctx, &m, func(keys []string) { got <- keys })
	select {
	case keys := <-got:
		assert.ElementsMatch(t, []string{"a", "b"}, keys, "first call")
	case <-time.After(5 * time.Second):
		t.Fatal("no first call")
	}
	Store(&m, "a", &a{3})
	select {
	case keys := <-got:
		assert.Equal(t, []string{"a"}, keys)
	case <-time.After(5 * time.Second):
		t.Fatal("no call after a store")
	}
}
