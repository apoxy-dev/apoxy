// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package gatewayapi

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"k8s.io/utils/ptr"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/apoxy-dev/apoxy/pkg/gateway/ir"
)

func TestProcessTimeout_Defaults(t *testing.T) {
	cases := []struct {
		name             string
		rule             gwapiv1.HTTPRouteRule
		wantRequest      time.Duration
		wantIdle         time.Duration
		wantHasIdle      bool
		wantHasRequest   bool
	}{
		{
			name:           "no timeouts uses platform defaults",
			rule:           gwapiv1.HTTPRouteRule{},
			wantRequest:    100 * time.Second,
			wantIdle:       60 * time.Second,
			wantHasIdle:    true,
			wantHasRequest: true,
		},
		{
			name: "request override leaves idle at default",
			rule: gwapiv1.HTTPRouteRule{
				Timeouts: &gwapiv1.HTTPRouteTimeouts{
					Request: ptr.To(gwapiv1.Duration("5s")),
				},
			},
			wantRequest:    5 * time.Second,
			wantIdle:       60 * time.Second,
			wantHasIdle:    true,
			wantHasRequest: true,
		},
		{
			name: "backendRequest override leaves idle at default",
			rule: gwapiv1.HTTPRouteRule{
				Timeouts: &gwapiv1.HTTPRouteTimeouts{
					BackendRequest: ptr.To(gwapiv1.Duration("7s")),
				},
			},
			wantRequest:    7 * time.Second,
			wantIdle:       60 * time.Second,
			wantHasIdle:    true,
			wantHasRequest: true,
		},
		{
			name: "backendRequest wins over request for request timeout, idle untouched",
			rule: gwapiv1.HTTPRouteRule{
				Timeouts: &gwapiv1.HTTPRouteTimeouts{
					Request:        ptr.To(gwapiv1.Duration("3s")),
					BackendRequest: ptr.To(gwapiv1.Duration("9s")),
				},
			},
			wantRequest:    9 * time.Second,
			wantIdle:       60 * time.Second,
			wantHasIdle:    true,
			wantHasRequest: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ir := &ir.HTTPRoute{}
			processTimeout(ir, tc.rule)

			if !assert.NotNil(t, ir.Timeout) || !assert.NotNil(t, ir.Timeout.HTTP) {
				return
			}

			if tc.wantHasRequest {
				if assert.NotNil(t, ir.Timeout.HTTP.RequestTimeout) {
					assert.Equal(t, tc.wantRequest, ir.Timeout.HTTP.RequestTimeout.Duration)
				}
			} else {
				assert.Nil(t, ir.Timeout.HTTP.RequestTimeout)
			}

			if tc.wantHasIdle {
				if assert.NotNil(t, ir.Timeout.HTTP.ConnectionIdleTimeout, "ConnectionIdleTimeout must be defaulted to avoid UC from server-first close") {
					assert.Equal(t, tc.wantIdle, ir.Timeout.HTTP.ConnectionIdleTimeout.Duration)
				}
			} else {
				assert.Nil(t, ir.Timeout.HTTP.ConnectionIdleTimeout)
			}
		})
	}
}

func TestSetDefaultRetry(t *testing.T) {
	cases := []struct {
		name        string
		existing    *ir.Retry
		wantNumRetr uint32
		wantIdemp   bool
		wantNoop    bool
	}{
		{
			name:        "nil retry gets defaulted to 1 attempt, idempotent-only",
			existing:    nil,
			wantNumRetr: 1,
			wantIdemp:   true,
		},
		{
			name:        "non-nil retry is left alone (caller already populated it)",
			existing:    &ir.Retry{NumRetries: ptr.To(uint32(3))},
			wantNumRetr: 3,
			wantIdemp:   false,
			wantNoop:    true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			irRoute := &ir.HTTPRoute{Retry: tc.existing}
			setDefaultRetry(irRoute)

			if !assert.NotNil(t, irRoute.Retry) {
				return
			}
			if assert.NotNil(t, irRoute.Retry.NumRetries) {
				assert.Equal(t, tc.wantNumRetr, *irRoute.Retry.NumRetries)
			}
			if tc.wantNoop {
				assert.Nil(t, irRoute.Retry.IdempotentOnly, "must not stamp IdempotentOnly onto a user-supplied Retry")
			} else {
				if assert.NotNil(t, irRoute.Retry.IdempotentOnly) {
					assert.Equal(t, tc.wantIdemp, *irRoute.Retry.IdempotentOnly)
				}
			}
		})
	}
}
