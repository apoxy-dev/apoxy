// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package translator

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEnvoyTextLogFormat checks the default access log format. Every line must
// stay one JSON object, and the timing keys that split the time in the proxy
// must stay in it.
func TestEnvoyTextLogFormat(t *testing.T) {
	require.True(t, strings.HasSuffix(EnvoyTextLogFormat, "}\n"), "the format must end one JSON object per line")

	var fields map[string]string
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSuffix(EnvoyTextLogFormat, "\n")), &fields))

	cases := []struct {
		key  string
		want string
	}{
		{key: "start_time", want: "%START_TIME%"},
		{key: "duration", want: "%DURATION%"},
		{key: "route_name", want: "%ROUTE_NAME%"},
		{key: "request_tx_duration", want: "%REQUEST_TX_DURATION%"},
		{key: "filter_duration", want: "%COMMON_DURATION(DS_RX_BEG:US_TX_BEG:ms)%"},
		{key: "response_duration", want: "%RESPONSE_DURATION%"},
	}

	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			assert.Equal(t, tc.want, fields[tc.key])
		})
	}
}
