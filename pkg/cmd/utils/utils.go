package utils

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

// IsInteractive reports whether both stdin and stdout are connected to a TTY.
func IsInteractive() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

// ReadFileAsString returns a file as a string or an error.
func ReadFileAsString(filename string) (string, error) {
	slog.Debug("Reading from file", "filename", filename)
	data, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ReadStdInAsString returns stdin as a string or an error.
func ReadStdInAsString() (string, error) {
	slog.Debug("Reading from stdin")
	scanner := bufio.NewScanner(os.Stdin)
	var input string
	for scanner.Scan() {
		text := scanner.Text()
		input += text + "\n"
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("Error reading from stdin: %v", err)
	}
	return input, nil
}

// YAMLToJSON converts YAML to JSON.
func YAMLToJSON(yml string) (string, error) {
	var data interface{}
	err := yaml.Unmarshal([]byte(yml), &data)
	if err != nil {
		return "", err
	}
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	return string(jsonBytes), nil
}

// LabelsToString converts a map of labels to a string.
func LabelsToString(labels map[string]string) string {
	var l []string
	for k, v := range labels {
		l = append(l, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(l, ",")
}
