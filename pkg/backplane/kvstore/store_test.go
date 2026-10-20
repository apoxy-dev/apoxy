package kvstore

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLeave(t *testing.T) {
	t.Run("runs once and every caller shares the channel", func(t *testing.T) {
		s := New("ns", "app=x")
		var calls atomic.Int32
		release := make(chan struct{})
		s.shutdown = func(context.Context) error {
			calls.Add(1)
			<-release
			return nil
		}

		var wg sync.WaitGroup
		chs := make(chan (<-chan struct{}), 32)
		for i := 0; i < 32; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				chs <- s.Leave()
			}()
		}
		wg.Wait()
		close(chs)
		assert.ErrorContains(t, s.LeaveErr(), "not finished")

		close(release)
		first := s.Leave()
		for ch := range chs {
			assert.Equal(t, first, ch)
		}
		select {
		case <-first:
		case <-time.After(5 * time.Second):
			t.Fatal("leave did not finish")
		}
		assert.NoError(t, s.LeaveErr())
		require.NoError(t, s.Stop(context.Background()))
		assert.Equal(t, int32(1), calls.Load())
	})

	t.Run("error propagates", func(t *testing.T) {
		s := NewDev()
		boom := errors.New("boom")
		s.shutdown = func(context.Context) error { return boom }
		<-s.Leave()
		assert.ErrorIs(t, s.LeaveErr(), boom)
		assert.ErrorIs(t, s.Stop(context.Background()), boom)
	})

	t.Run("a hung shutdown is bounded", func(t *testing.T) {
		s := New("ns", "app=x")
		s.leaveTimeout = 50 * time.Millisecond
		hang := make(chan struct{})
		defer close(hang)
		s.shutdown = func(context.Context) error {
			<-hang
			return nil
		}
		select {
		case <-s.Leave():
		case <-time.After(5 * time.Second):
			t.Fatal("leave did not time out")
		}
		assert.ErrorIs(t, s.LeaveErr(), context.DeadlineExceeded)
	})

	t.Run("not started", func(t *testing.T) {
		s := New("ns", "app=x")
		<-s.Leave()
		assert.ErrorContains(t, s.LeaveErr(), "not started")
	})

	t.Run("stop waits until ctx is done", func(t *testing.T) {
		s := New("ns", "app=x")
		hang := make(chan struct{})
		defer close(hang)
		s.shutdown = func(context.Context) error {
			<-hang
			return nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		assert.ErrorIs(t, s.Stop(ctx), context.DeadlineExceeded)
	})
}
