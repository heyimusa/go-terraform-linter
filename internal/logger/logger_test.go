package logger

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestNewLogger(t *testing.T) {
	tests := []struct {
		name     string
		level    LogLevel
		output   *os.File
		expected LogLevel
	}{
		{
			name:     "debug level",
			level:    DEBUG,
			output:   nil,
			expected: DEBUG,
		},
		{
			name:     "info level",
			level:    INFO,
			output:   nil,
			expected: INFO,
		},
		{
			name:     "warn level",
			level:    WARN,
			output:   nil,
			expected: WARN,
		},
		{
			name:     "error level",
			level:    ERROR,
			output:   nil,
			expected: ERROR,
		},
		{
			name:     "fatal level",
			level:    FATAL,
			output:   nil,
			expected: FATAL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := NewLogger(tt.level, tt.output)
			if logger == nil {
				t.Fatal("Expected logger object, got nil")
			}
			if logger.GetLevel() != tt.expected {
				t.Errorf("Expected level %v, got %v", tt.expected, logger.GetLevel())
			}
		})
	}
}

func TestLoggerLevels(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(DEBUG, &buf)

	tests := []struct {
		name      string
		logFunc   func(string, ...map[string]interface{})
		message   string
		metadata  map[string]interface{}
		shouldLog bool
	}{
		{
			name:      "debug message",
			logFunc:   logger.Debug,
			message:   "Debug message",
			metadata:  map[string]interface{}{"key": "value"},
			shouldLog: true,
		},
		{
			name:      "info message",
			logFunc:   logger.Info,
			message:   "Info message",
			metadata:  map[string]interface{}{"key": "value"},
			shouldLog: true,
		},
		{
			name:      "warn message",
			logFunc:   logger.Warn,
			message:   "Warn message",
			metadata:  map[string]interface{}{"key": "value"},
			shouldLog: true,
		},
		{
			name:      "error message",
			logFunc:   logger.Error,
			message:   "Error message",
			metadata:  map[string]interface{}{"key": "value"},
			shouldLog: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf.Reset()
			tt.logFunc(tt.message, tt.metadata)

			output := buf.String()
			if tt.shouldLog {
				if output == "" {
					t.Error("Expected log output, got empty string")
				}
				if !strings.Contains(output, tt.message) {
					t.Errorf("Expected output to contain '%s', got: %s", tt.message, output)
				}
			} else {
				if output != "" {
					t.Errorf("Expected no log output, got: %s", output)
				}
			}
		})
	}
}

func TestLoggerLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(WARN, &buf) // Only WARN and above

	tests := []struct {
		name      string
		logFunc   func(string, ...map[string]interface{})
		message   string
		shouldLog bool
	}{
		{
			name:      "debug message (filtered)",
			logFunc:   logger.Debug,
			message:   "Debug message",
			shouldLog: false,
		},
		{
			name:      "info message (filtered)",
			logFunc:   logger.Info,
			message:   "Info message",
			shouldLog: false,
		},
		{
			name:      "warn message (logged)",
			logFunc:   logger.Warn,
			message:   "Warn message",
			shouldLog: true,
		},
		{
			name:      "error message (logged)",
			logFunc:   logger.Error,
			message:   "Error message",
			shouldLog: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf.Reset()
			tt.logFunc(tt.message, map[string]interface{}{})

			output := buf.String()
			if tt.shouldLog {
				if output == "" {
					t.Error("Expected log output, got empty string")
				}
				if !strings.Contains(output, tt.message) {
					t.Errorf("Expected output to contain '%s', got: %s", tt.message, output)
				}
			} else {
				if output != "" {
					t.Errorf("Expected no log output, got: %s", output)
				}
			}
		})
	}
}

func TestLoggerMetadata(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(INFO, &buf)

	tests := []struct {
		name     string
		message  string
		metadata map[string]interface{}
		contains []string
	}{
		{
			name:    "string metadata",
			message: "Test message",
			metadata: map[string]interface{}{
				"file": "test.tf",
				"rule": "TEST_RULE",
			},
			contains: []string{"file", "test.tf", "rule", "TEST_RULE"},
		},
		{
			name:    "numeric metadata",
			message: "Test message",
			metadata: map[string]interface{}{
				"line":  10,
				"count": 5,
			},
			contains: []string{"line", "10", "count", "5"},
		},
		{
			name:    "boolean metadata",
			message: "Test message",
			metadata: map[string]interface{}{
				"enabled": true,
				"valid":   false,
			},
			contains: []string{"enabled", "true", "valid", "false"},
		},
		{
			name:     "nil metadata",
			message:  "Test message",
			metadata: nil,
			contains: []string{"Test message"},
		},
		{
			name:     "empty metadata",
			message:  "Test message",
			metadata: map[string]interface{}{},
			contains: []string{"Test message"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf.Reset()
			logger.Info(tt.message, tt.metadata)

			output := buf.String()
			for _, expected := range tt.contains {
				if !strings.Contains(output, expected) {
					t.Errorf("Expected output to contain '%s', got: %s", expected, output)
				}
			}
		})
	}
}

func TestLoggerWithFile(t *testing.T) {
	// Create temporary file for testing
	tmpFile, err := os.CreateTemp("", "test-log-*.log")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	logger := NewLogger(INFO, tmpFile)

	// Log some messages
	logger.Info("Test info message", map[string]interface{}{"key": "value"})
	logger.Warn("Test warn message", nil)
	logger.Error("Test error message", map[string]interface{}{"error": "test"})

	// Read the file content
	content, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	output := string(content)
	
	// Check if all messages are in the file
	expectedMessages := []string{
		"Test info message",
		"Test warn message", 
		"Test error message",
	}

	for _, msg := range expectedMessages {
		if !strings.Contains(output, msg) {
			t.Errorf("Expected log file to contain '%s', got: %s", msg, output)
		}
	}
}

func TestLoggerConcurrency(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(INFO, &buf)

	// Test concurrent logging
	done := make(chan bool, 10)
	
	for i := 0; i < 10; i++ {
		go func(id int) {
			logger.Info("Concurrent message", map[string]interface{}{"goroutine": id})
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	output := buf.String()
	if output == "" {
		t.Error("Expected concurrent log output, got empty string")
	}

	// Count occurrences of "Concurrent message"
	count := strings.Count(output, "Concurrent message")
	if count != 10 {
		t.Errorf("Expected 10 concurrent messages, got %d", count)
	}
}

func TestLoggerEdgeCases(t *testing.T) {
	var buf bytes.Buffer
	logger := NewLogger(INFO, &buf)

	tests := []struct {
		name     string
		message  string
		metadata map[string]interface{}
	}{
		{
			name:     "empty message",
			message:  "",
			metadata: map[string]interface{}{"key": "value"},
		},
		{
			name:    "very long message",
			message: strings.Repeat("a", 1000),
			metadata: map[string]interface{}{},
		},
		{
			name:    "special characters",
			message: "Message with special chars: \n\t\r\"'\\",
			metadata: map[string]interface{}{
				"special": "\n\t\r\"'\\",
			},
		},
		{
			name:    "unicode characters",
			message: "Unicode: 你好世界 🚀 🔍",
			metadata: map[string]interface{}{
				"unicode": "🎯 ✨",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf.Reset()
			logger.Info(tt.message, tt.metadata)

			output := buf.String()
			if output == "" {
				t.Error("Expected log output, got empty string")
			}
		})
	}
}

// Benchmark tests
func BenchmarkLoggerInfo(b *testing.B) {
	var buf bytes.Buffer
	logger := NewLogger(INFO, &buf)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.Info("Benchmark message", map[string]interface{}{"iteration": i})
	}
}

func BenchmarkLoggerInfoWithoutMetadata(b *testing.B) {
	var buf bytes.Buffer
	logger := NewLogger(INFO, &buf)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.Info("Benchmark message", nil)
	}
}

func BenchmarkLoggerFiltered(b *testing.B) {
	var buf bytes.Buffer
	logger := NewLogger(ERROR, &buf) // Only ERROR level, DEBUG will be filtered

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.Debug("Filtered message", map[string]interface{}{"iteration": i})
	}
} 