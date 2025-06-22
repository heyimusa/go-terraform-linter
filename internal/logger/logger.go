package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"
)

// LogLevel represents the logging level
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	WARN
	ERROR
	FATAL
)

// String returns the string representation of LogLevel
func (l LogLevel) String() string {
	switch l {
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case WARN:
		return "WARN"
	case ERROR:
		return "ERROR"
	case FATAL:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

// Logger provides structured logging functionality
type Logger struct {
	level    LogLevel
	output   io.Writer
	logger   *log.Logger
	filePath string
}

// LogEntry represents a structured log entry
type LogEntry struct {
	Timestamp time.Time              `json:"timestamp"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	File      string                 `json:"file,omitempty"`
	Line      int                    `json:"line,omitempty"`
	Function  string                 `json:"function,omitempty"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
}

// NewLogger creates a new logger instance
func NewLogger(level LogLevel, output io.Writer) *Logger {
	if output == nil {
		output = os.Stdout
	}
	
	return &Logger{
		level:  level,
		output: output,
		logger: log.New(output, "", 0),
	}
}

// NewFileLogger creates a logger that writes to a file
func NewFileLogger(level LogLevel, filePath string) (*Logger, error) {
	// Ensure directory exists
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}
	
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}
	
	return &Logger{
		level:    level,
		output:   file,
		logger:   log.New(file, "", 0),
		filePath: filePath,
	}, nil
}

// Debug logs a debug message
func (l *Logger) Debug(message string, fields ...map[string]interface{}) {
	l.log(DEBUG, message, fields...)
}

// Info logs an info message
func (l *Logger) Info(message string, fields ...map[string]interface{}) {
	l.log(INFO, message, fields...)
}

// Warn logs a warning message
func (l *Logger) Warn(message string, fields ...map[string]interface{}) {
	l.log(WARN, message, fields...)
}

// Error logs an error message
func (l *Logger) Error(message string, fields ...map[string]interface{}) {
	l.log(ERROR, message, fields...)
}

// Fatal logs a fatal message and exits
func (l *Logger) Fatal(message string, fields ...map[string]interface{}) {
	l.log(FATAL, message, fields...)
	os.Exit(1)
}

// log is the internal logging method
func (l *Logger) log(level LogLevel, message string, fields ...map[string]interface{}) {
	if level < l.level {
		return
	}
	
	entry := LogEntry{
		Timestamp: time.Now(),
		Level:     level.String(),
		Message:   message,
	}
	
	if len(fields) > 0 {
		entry.Fields = fields[0]
	}
	
	// Format the log entry
	formatted := l.formatEntry(entry)
	l.logger.Print(formatted)
}

// formatEntry formats a log entry for output
func (l *Logger) formatEntry(entry LogEntry) string {
	// Simple format for now, can be enhanced with JSON or structured formats
	base := fmt.Sprintf("[%s] %s: %s", 
		entry.Timestamp.Format("2006-01-02 15:04:05"),
		entry.Level,
		entry.Message)
	
	if len(entry.Fields) > 0 {
		base += fmt.Sprintf(" | Fields: %v", entry.Fields)
	}
	
	return base
}

// SetLevel sets the logging level
func (l *Logger) SetLevel(level LogLevel) {
	l.level = level
}

// GetLevel returns the current logging level
func (l *Logger) GetLevel() LogLevel {
	return l.level
}

// Close closes the logger and any associated resources
func (l *Logger) Close() error {
	if l.filePath != "" {
		if closer, ok := l.output.(io.Closer); ok {
			return closer.Close()
		}
	}
	return nil
}

// PerformanceLogger provides performance tracking functionality
type PerformanceLogger struct {
	logger *Logger
	start  time.Time
}

// NewPerformanceLogger creates a new performance logger
func NewPerformanceLogger(logger *Logger) *PerformanceLogger {
	return &PerformanceLogger{
		logger: logger,
		start:  time.Now(),
	}
}

// StartTimer starts a new performance timer
func (pl *PerformanceLogger) StartTimer() {
	pl.start = time.Now()
}

// EndTimer logs the elapsed time since StartTimer
func (pl *PerformanceLogger) EndTimer(operation string) {
	elapsed := time.Since(pl.start)
	pl.logger.Info(fmt.Sprintf("Operation '%s' completed", operation), map[string]interface{}{
		"operation": operation,
		"duration":  elapsed.String(),
		"duration_ms": elapsed.Milliseconds(),
	})
}

// LogFileOperation logs file operation details
func (pl *PerformanceLogger) LogFileOperation(operation, filePath string, fileSize int64, duration time.Duration) {
	pl.logger.Info(fmt.Sprintf("File operation '%s' completed", operation), map[string]interface{}{
		"operation":  operation,
		"file_path":  filePath,
		"file_size":  fileSize,
		"duration":   duration.String(),
		"duration_ms": duration.Milliseconds(),
	})
}

// LogScanProgress logs scanning progress
func (pl *PerformanceLogger) LogScanProgress(current, total int, currentFile string) {
	percentage := float64(current) / float64(total) * 100
	pl.logger.Debug("Scan progress", map[string]interface{}{
		"current":     current,
		"total":       total,
		"percentage":  fmt.Sprintf("%.1f%%", percentage),
		"current_file": currentFile,
	})
}

// ErrorLogger provides specialized error logging
type ErrorLogger struct {
	logger *Logger
}

// NewErrorLogger creates a new error logger
func NewErrorLogger(logger *Logger) *ErrorLogger {
	return &ErrorLogger{logger: logger}
}

// LogParseError logs parsing errors with context
func (el *ErrorLogger) LogParseError(filePath string, error string, line int) {
	el.logger.Error("Failed to parse Terraform file", map[string]interface{}{
		"file_path": filePath,
		"error":     error,
		"line":      line,
		"type":      "parse_error",
	})
}

// LogRuleError logs rule execution errors
func (el *ErrorLogger) LogRuleError(ruleName, filePath string, error string) {
	el.logger.Error("Rule execution failed", map[string]interface{}{
		"rule_name": ruleName,
		"file_path": filePath,
		"error":     error,
		"type":      "rule_error",
	})
}

// LogCacheError logs cache-related errors
func (el *ErrorLogger) LogCacheError(operation string, error string) {
	el.logger.Error("Cache operation failed", map[string]interface{}{
		"operation": operation,
		"error":     error,
		"type":      "cache_error",
	})
}

// LogConfigurationError logs configuration errors
func (el *ErrorLogger) LogConfigurationError(configPath string, error string) {
	el.logger.Error("Configuration error", map[string]interface{}{
		"config_path": configPath,
		"error":       error,
		"type":        "config_error",
	})
} 