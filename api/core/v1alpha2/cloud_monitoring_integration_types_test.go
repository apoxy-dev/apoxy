package v1alpha2

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestCloudMonitoringIntegrationSpec_EnabledFalse_PreservedInJSON verifies that
// setting Enabled=false survives a JSON round-trip. If the field uses omitempty,
// false (the zero value) is stripped from the serialized JSON, and the
// apiserver's +kubebuilder:default=true re-applies true on the next read —
// making it impossible to disable an integration.
func TestCloudMonitoringIntegrationSpec_EnabledFalse_PreservedInJSON(t *testing.T) {
	spec := CloudMonitoringIntegrationSpec{
		Enabled: false,
		DatadogCredentials: &DatadogCredentials{
			APIKey: "test-key",
			Site:   "us1.datadoghq.com",
		},
	}

	data, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("Failed to marshal spec: %v", err)
	}

	// The "enabled" field MUST be present in the serialized JSON even when
	// false, so that the apiserver does not re-apply the default.
	if !strings.Contains(string(data), `"enabled"`) {
		t.Fatalf("enabled:false was dropped from JSON (omitempty bug); serialized: %s", data)
	}

	var decoded CloudMonitoringIntegrationSpec
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal spec: %v", err)
	}

	if decoded.Enabled != false {
		t.Fatalf("Expected Enabled=false after round-trip, got %v", decoded.Enabled)
	}
}
