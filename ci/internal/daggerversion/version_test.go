// Package daggerversion checks that the CI install of the Dagger CLI matches dagger.json.
package daggerversion

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

func TestSetupDaggerVersion(t *testing.T) {
	data, err := os.ReadFile("../../../dagger.json")
	if err != nil {
		t.Fatal(err)
	}
	var mod struct {
		EngineVersion string `json:"engineVersion"`
	}
	if err := json.Unmarshal(data, &mod); err != nil {
		t.Fatal(err)
	}
	if mod.EngineVersion == "" {
		t.Fatal("dagger.json has no engineVersion")
	}

	data, err = os.ReadFile("../../../.github/actions/setup-dagger/action.yml")
	if err != nil {
		t.Fatal(err)
	}
	var action struct {
		Runs struct {
			Steps []struct {
				Uses string            `json:"uses"`
				With map[string]string `json:"with"`
			} `json:"steps"`
		} `json:"runs"`
	}
	if err := yaml.Unmarshal(data, &action); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range action.Runs.Steps {
		if !strings.HasPrefix(s.Uses, "dagger/dagger-for-github@") {
			continue
		}
		found = true
		if want := strings.TrimPrefix(mod.EngineVersion, "v"); s.With["version"] != want {
			t.Errorf("setup-dagger installs Dagger %q, but dagger.json has engineVersion %s: make them the same",
				s.With["version"], mod.EngineVersion)
		}
	}
	if !found {
		t.Error("setup-dagger has no dagger/dagger-for-github step")
	}
}
