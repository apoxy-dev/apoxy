// Package helmrules turns rendered chart objects into the files their
// checkers read.
package helmrules

import (
	"encoding/json"
	"fmt"

	"sigs.k8s.io/yaml"
)

// RulesFromPrometheusRule returns the spec of one rendered PrometheusRule as
// the rule file promtool reads.
func RulesFromPrometheusRule(manifest string) (string, error) {
	var obj struct {
		Kind string         `json:"kind"`
		Spec map[string]any `json:"spec"`
	}
	if err := yaml.Unmarshal([]byte(manifest), &obj); err != nil {
		return "", fmt.Errorf("parse the rendered manifest: %w", err)
	}
	if obj.Kind != "PrometheusRule" {
		return "", fmt.Errorf("the rendered manifest is a %q, not a PrometheusRule", obj.Kind)
	}
	if len(obj.Spec) == 0 {
		return "", fmt.Errorf("the rendered PrometheusRule has no spec")
	}
	out, err := yaml.Marshal(obj.Spec)
	if err != nil {
		return "", fmt.Errorf("write the rule file: %w", err)
	}
	return string(out), nil
}

// CheckDashboard returns an error when the Grafana dashboard is not a JSON
// object with panels.
func CheckDashboard(content string) error {
	var dashboard struct {
		Panels []json.RawMessage `json:"panels"`
	}
	if err := json.Unmarshal([]byte(content), &dashboard); err != nil {
		return fmt.Errorf("parse the dashboard: %w", err)
	}
	if len(dashboard.Panels) == 0 {
		return fmt.Errorf("the dashboard has no panels")
	}
	return nil
}
