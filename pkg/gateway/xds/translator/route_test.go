// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package translator

import (
	"testing"

	matcherv3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	"github.com/apoxy-dev/apoxy/pkg/gateway/ir"
)

func TestBuildRetryPolicy_IdempotentOnly(t *testing.T) {
	cases := []struct {
		name     string
		retry    *ir.Retry
		wantHdrs bool
	}{
		{
			name:     "IdempotentOnly=true emits :method regex matcher",
			retry:    &ir.Retry{NumRetries: ptr.To(uint32(1)), IdempotentOnly: ptr.To(true)},
			wantHdrs: true,
		},
		{
			name:     "IdempotentOnly=false emits no method matcher",
			retry:    &ir.Retry{NumRetries: ptr.To(uint32(1)), IdempotentOnly: ptr.To(false)},
			wantHdrs: false,
		},
		{
			name:     "IdempotentOnly nil emits no method matcher",
			retry:    &ir.Retry{NumRetries: ptr.To(uint32(2))},
			wantHdrs: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			route := &ir.HTTPRoute{Retry: tc.retry}
			rp, err := buildRetryPolicy(route)
			require.NoError(t, err)
			require.NotNil(t, rp)

			if !tc.wantHdrs {
				assert.Empty(t, rp.RetriableRequestHeaders, "must not constrain methods unless explicitly opted in")
				return
			}

			require.Len(t, rp.RetriableRequestHeaders, 1)
			hm := rp.RetriableRequestHeaders[0]
			assert.Equal(t, ":method", hm.Name)
			stringMatch := hm.GetStringMatch()
			require.NotNil(t, stringMatch, "must use StringMatch (regex on :method)")
			sr, ok := stringMatch.MatchPattern.(*matcherv3.StringMatcher_SafeRegex)
			require.True(t, ok, "must use SafeRegex, not Exact/Prefix")
			assert.Equal(t, idempotentMethodsRegex, sr.SafeRegex.Regex)
		})
	}
}
