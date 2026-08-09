package api

import (
	"errors"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/require"
)

func TestClientControlCloseSignals(t *testing.T) {
	cases := []struct {
		name         string
		cause        error
		clientClosed bool
		wantDrain    bool
		wantLost     bool
	}{
		{
			name:      "graceful relay drain",
			cause:     &quic.ApplicationError{ErrorCode: quic.ApplicationErrorCode(http3.ErrCodeNoError)},
			wantDrain: true,
		},
		{
			name:     "abrupt connection loss",
			cause:    errors.New("timeout: no recent network activity"),
			wantLost: true,
		},
		{
			name:         "client close",
			cause:        &quic.ApplicationError{ErrorCode: quic.ApplicationErrorCode(http3.ErrCodeNoError)},
			clientClosed: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Client{
				draining: make(chan struct{}),
				lost:     make(chan struct{}),
			}
			c.closed.Store(tc.clientClosed)
			c.handleControlClose(tc.cause)

			require.Equal(t, tc.wantDrain, channelClosed(c.Draining()))
			require.Equal(t, tc.wantLost, channelClosed(c.Lost()))
		})
	}
}

func TestClientControlConnectionLivenessConfig(t *testing.T) {
	c, err := NewClient(ClientOptions{
		BaseURL:    "https://relay.example:6081",
		Agent:      "agent-a",
		TunnelName: "default",
		Token:      "token",
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, c.Close()) })

	require.Equal(t, 5*time.Second, c.h3.QUICConfig.KeepAlivePeriod)
	require.Equal(t, 15*time.Second, c.h3.QUICConfig.MaxIdleTimeout)
}

func channelClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}
