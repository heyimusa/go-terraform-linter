package tests

import (
	"os"
	"testing"
	"github.com/heyimusa/go-terraform-linter/internal/parser"
)

// parseTestConfig creates a temp file, writes the config, parses it, and cleans up.
func parseTestConfig(t *testing.T, config string) *parser.Config {
	tmpFile, err := os.CreateTemp("", "test-*.tf")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	if _, err := tmpFile.Write([]byte(config)); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	parser := parser.NewParser()
	parsedConfig, err := parser.ParseFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to parse test config: %v", err)
	}
	return parsedConfig
} 