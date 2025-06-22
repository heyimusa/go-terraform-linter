 # Go Terraform Linter API Documentation 📚

This document provides comprehensive API documentation for the Go Terraform Linter, including interfaces, types, and functions for extending and integrating with the linter.

## Table of Contents

- [Core Interfaces](#core-interfaces)
- [Data Types](#data-types)
- [Parser API](#parser-api)
- [Rules Engine API](#rules-engine-api)
- [Caching API](#caching-api)
- [Logging API](#logging-api)
- [Validation API](#validation-api)
- [Report Generation API](#report-generation-api)
- [CLI Integration](#cli-integration)
- [Examples](#examples)

## Core Interfaces 🔧

### Rule Interface

The core interface that all security rules must implement:

```go
type Rule interface {
    GetName() string
    GetDescription() string
    GetSeverity() string
    Check(config *parser.Config) []types.Issue
}
```

**Methods:**
- `GetName()`: Returns the unique rule identifier (e.g., "AZURE_EXPOSED_SECRETS")
- `GetDescription()`: Returns a human-readable description of the rule
- `GetSeverity()`: Returns the rule severity ("CRITICAL", "HIGH", "MEDIUM", "LOW")
- `Check(config)`: Executes the rule logic and returns detected issues

### Linter Interface

The main linter interface for scanning Terraform configurations:

```go
type Linter interface {
    Scan(path string, options *ScanOptions) (*ScanResult, error)
    ScanFile(filePath string, options *ScanOptions) (*ScanResult, error)
    ScanString(content string, options *ScanOptions) (*ScanResult, error)
}
```

**Methods:**
- `Scan(path)`: Scans a directory for Terraform files
- `ScanFile(filePath)`: Scans a single Terraform file
- `ScanString(content)`: Scans Terraform content from a string

## Data Types 📊

### Core Types

```go
// Issue represents a detected security issue
type Issue struct {
    Rule        string `json:"rule"`
    Severity    string `json:"severity"`
    Message     string `json:"message"`
    Description string `json:"description"`
    Line        int    `json:"line"`
    Column      int    `json:"column"`
    File        string `json:"file"`
    Confidence  int    `json:"confidence"` // 0-100
}

// Block represents a Terraform configuration block
type Block struct {
    Type      string                 `json:"type"`
    Labels    []string               `json:"labels"`
    Attributes map[string]*Attribute  `json:"attributes"`
    Blocks    []*Block               `json:"blocks"`
    Range     *hcl.Range             `json:"range"`
}

// Attribute represents a Terraform attribute
type Attribute struct {
    Name     string      `json:"name"`
    Value    interface{} `json:"value"`
    RawValue string      `json:"raw_value"` // Original string value
    Range    *hcl.Range  `json:"range"`
}

// Config represents a parsed Terraform configuration
type Config struct {
    Blocks []*Block `json:"blocks"`
    Files  []string `json:"files"`
}

// ScanResult represents the result of a linter scan
type ScanResult struct {
    Issues       []Issue `json:"issues"`
    FilesScanned int     `json:"files_scanned"`
    Duration     string  `json:"duration"`
    CacheHitRate float64 `json:"cache_hit_rate"`
    Errors       []error `json:"errors"`
}

// ScanOptions configures the scanning behavior
type ScanOptions struct {
    SeverityFilter []string          `json:"severity_filter"`
    ExcludePatterns []string         `json:"exclude_patterns"`
    IncludePatterns []string         `json:"include_patterns"`
    EnableCache     bool             `json:"enable_cache"`
    CacheDir        string           `json:"cache_dir"`
    LogLevel        string           `json:"log_level"`
    MaxWorkers      int              `json:"max_workers"`
    CustomRules     []Rule           `json:"custom_rules"`
    ConfigFile      string           `json:"config_file"`
}
```

### Configuration Types

```go
// Config represents the linter configuration
type Config struct {
    Exclude        []string            `yaml:"exclude" json:"exclude"`
    Severity       map[string]string   `yaml:"severity" json:"severity"`
    Performance    PerformanceConfig   `yaml:"performance" json:"performance"`
    Logging        LoggingConfig       `yaml:"logging" json:"logging"`
    CustomRules    []CustomRule        `yaml:"custom_rules" json:"custom_rules"`
}

type PerformanceConfig struct {
    MaxWorkers    int    `yaml:"max_workers" json:"max_workers"`
    EnableCache   bool   `yaml:"enable_cache" json:"enable_cache"`
    CacheDir      string `yaml:"cache_dir" json:"cache_dir"`
}

type LoggingConfig struct {
    Level                      string `yaml:"level" json:"level"`
    File                       string `yaml:"file" json:"file"`
    EnablePerformanceTracking  bool   `yaml:"enable_performance_tracking" json:"enable_performance_tracking"`
}

type CustomRule struct {
    Name         string   `yaml:"name" json:"name"`
    Description  string   `yaml:"description" json:"description"`
    Severity     string   `yaml:"severity" json:"severity"`
    Pattern      string   `yaml:"pattern" json:"pattern"`
    ResourceTypes []string `yaml:"resource_types" json:"resource_types"`
}
```

## Parser API 🔍

### Parser Functions

```go
// ParseFile parses a single Terraform file
func ParseFile(filePath string) (*Config, error)

// ParseString parses Terraform content from a string
func ParseString(content string) (*Config, error)

// ParseDirectory parses all Terraform files in a directory
func ParseDirectory(dirPath string) (*Config, error)

// IsTerraformFile checks if a file is a Terraform file
func IsTerraformFile(filePath string) bool

// GetSupportedExtensions returns supported file extensions
func GetSupportedExtensions() []string
```

### Parser Options

```go
type ParserOptions struct {
    IncludeHidden bool     // Include hidden files
    MaxFileSize   int64    // Maximum file size to parse
    StrictMode    bool     // Strict parsing mode
    IgnoreErrors  bool     // Continue on parse errors
}
```

## Rules Engine API ⚙️

### Rule Registration

```go
// RegisterRule registers a new rule with the engine
func RegisterRule(rule Rule) error

// GetRegisteredRules returns all registered rules
func GetRegisteredRules() []Rule

// GetRulesByProvider returns rules for a specific cloud provider
func GetRulesByProvider(provider string) []Rule

// GetRulesBySeverity returns rules filtered by severity
func GetRulesBySeverity(severity string) []Rule
```

### Rule Execution

```go
// ExecuteRules runs all registered rules against a configuration
func ExecuteRules(config *Config, options *RuleOptions) []Issue

// ExecuteRule runs a specific rule against a configuration
func ExecuteRule(rule Rule, config *Config) []Issue

// ValidateRule validates a rule implementation
func ValidateRule(rule Rule) error
```

### Rule Options

```go
type RuleOptions struct {
    EnableValidation bool     // Enable rule validation
    ConfidenceThreshold int   // Minimum confidence score
    SkipRules        []string // Rules to skip
    CustomRules      []Rule   // Custom rules to include
}
```

## Caching API 💾

### Cache Interface

```go
type Cache interface {
    Get(key string) (interface{}, bool)
    Set(key string, value interface{}, expiration time.Duration)
    Delete(key string)
    Clear()
    GetStats() *CacheStats
}

type CacheStats struct {
    Hits       int64
    Misses     int64
    HitRate    float64
    Size       int
    Expired    int64
}
```

### Cache Functions

```go
// NewFileCache creates a new file-based cache
func NewFileCache(cacheDir string) (Cache, error)

// NewMemoryCache creates a new in-memory cache
func NewMemoryCache() Cache

// GenerateCacheKey generates a cache key for a file
func GenerateCacheKey(filePath string, content []byte) string

// ClearCache clears the cache directory
func ClearCache(cacheDir string) error
```

### Cache Configuration

```go
type CacheConfig struct {
    Directory   string        `json:"directory"`
    Expiration  time.Duration `json:"expiration"`
    MaxSize     int64         `json:"max_size"`
    Compression bool          `json:"compression"`
}
```

## Logging API 📝

### Logger Interface

```go
type Logger interface {
    Debug(msg string, fields ...Field)
    Info(msg string, fields ...Field)
    Warn(msg string, fields ...Field)
    Error(msg string, fields ...Field)
    Fatal(msg string, fields ...Field)
    WithFields(fields ...Field) Logger
}

type Field struct {
    Key   string
    Value interface{}
}
```

### Logger Functions

```go
// NewLogger creates a new logger instance
func NewLogger(config *LogConfig) (Logger, error)

// SetGlobalLogger sets the global logger instance
func SetGlobalLogger(logger Logger)

// GetGlobalLogger returns the global logger instance
func GetGlobalLogger() Logger

// Field creates a new log field
func Field(key string, value interface{}) Field
```

### Log Configuration

```go
type LogConfig struct {
    Level      string `json:"level"`
    Format     string `json:"format"` // "json" or "text"
    Output     string `json:"output"` // "stdout", "stderr", or file path
    EnableTime bool   `json:"enable_time"`
    EnableCaller bool `json:"enable_caller"`
}
```

## Validation API ✅

### Validator Interface

```go
type Validator interface {
    ValidateIssue(block *Block, ruleName string) bool
    GetConfidence(block *Block, ruleName string) int
    AddValidationRule(rule ValidationRule) error
    RemoveValidationRule(ruleName string) error
}

type ValidationRule interface {
    GetName() string
    Validate(block *Block, issue *Issue) bool
    GetConfidence(block *Block, issue *Issue) int
}
```

### Validation Functions

```go
// NewValidator creates a new validator instance
func NewValidator(config *ValidationConfig) (Validator, error)

// ValidateIssue validates a detected issue
func ValidateIssue(block *Block, ruleName string) bool

// GetConfidence calculates confidence score for an issue
func GetConfidence(block *Block, ruleName string) int

// AddWhitelist adds a whitelist pattern
func AddWhitelist(pattern string) error

// AddBlacklist adds a blacklist pattern
func AddBlacklist(pattern string) error
```

### Validation Configuration

```go
type ValidationConfig struct {
    EnableValidation bool     `json:"enable_validation"`
    ConfidenceThreshold int   `json:"confidence_threshold"`
    WhitelistPatterns []string `json:"whitelist_patterns"`
    BlacklistPatterns []string `json:"blacklist_patterns"`
    CustomRules       []ValidationRule `json:"custom_rules"`
}
```

## Report Generation API 📊

### Report Interface

```go
type Report interface {
    Generate(result *ScanResult, format string) ([]byte, error)
    GetSupportedFormats() []string
}

type ReportConfig struct {
    Format      string `json:"format"`
    OutputFile  string `json:"output_file"`
    IncludeStats bool  `json:"include_stats"`
    Colorize    bool  `json:"colorize"`
}
```

### Report Functions

```go
// NewReport creates a new report generator
func NewReport(config *ReportConfig) (Report, error)

// GenerateReport generates a report in the specified format
func GenerateReport(result *ScanResult, format string) ([]byte, error)

// GetSupportedFormats returns supported report formats
func GetSupportedFormats() []string

// ValidateFormat validates a report format
func ValidateFormat(format string) bool
```

### Report Formats

Supported report formats:
- `text`: Human-readable text output
- `json`: JSON format for programmatic consumption
- `sarif`: SARIF format for GitHub Security tab
- `html`: HTML report with detailed analysis
- `csv`: CSV format for spreadsheet analysis

## CLI Integration 🖥️

### CLI Commands

```go
// NewRootCommand creates the root CLI command
func NewRootCommand() *cobra.Command

// AddScanCommand adds the scan command
func AddScanCommand(root *cobra.Command)

// AddVersionCommand adds the version command
func AddVersionCommand(root *cobra.Command)

// Execute runs the CLI application
func Execute() error
```

### CLI Options

```go
type CLIOptions struct {
    ConfigFile   string   `json:"config_file"`
    OutputFormat string   `json:"output_format"`
    OutputFile   string   `json:"output_file"`
    Severity     []string `json:"severity"`
    Exclude      []string `json:"exclude"`
    Include      []string `json:"include"`
    Verbose      bool     `json:"verbose"`
    Quiet        bool     `json:"quiet"`
    ClearCache   bool     `json:"clear_cache"`
    LogLevel     string   `json:"log_level"`
    CacheDir     string   `json:"cache_dir"`
    MaxWorkers   int      `json:"max_workers"`
}
```

## Examples 💡

### Creating a Custom Rule

```go
package custom

import (
    "github.com/heyimusa/go-terraform-linter/internal/parser"
    "github.com/heyimusa/go-terraform-linter/internal/types"
)

type CustomSecurityRule struct{}

func (r *CustomSecurityRule) GetName() string {
    return "CUSTOM_SECURITY_RULE"
}

func (r *CustomSecurityRule) GetDescription() string {
    return "Detects custom security misconfiguration"
}

func (r *CustomSecurityRule) GetSeverity() string {
    return "HIGH"
}

func (r *CustomSecurityRule) Check(config *parser.Config) []types.Issue {
    var issues []types.Issue
    
    for _, block := range config.Blocks {
        if r.detectIssue(block) {
            issues = append(issues, types.Issue{
                Rule:        r.GetName(),
                Severity:    r.GetSeverity(),
                Message:     "Custom security issue detected",
                Description: "Detailed description and fix suggestion",
                Line:        block.Range.Start.Line,
                Confidence:  85,
            })
        }
    }
    
    return issues
}

func (r *CustomSecurityRule) detectIssue(block *types.Block) bool {
    // Your detection logic here
    return false
}
```

### Using the Linter Programmatically

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/heyimusa/go-terraform-linter/internal/linter"
    "github.com/heyimusa/go-terraform-linter/internal/logger"
)

func main() {
    // Initialize logger
    logConfig := &logger.LogConfig{
        Level:  "info",
        Format: "text",
        Output: "stdout",
    }
    
    logger, err := logger.NewLogger(logConfig)
    if err != nil {
        log.Fatal(err)
    }
    
    // Create linter instance
    linter := linter.NewLinter()
    
    // Configure scan options
    options := &linter.ScanOptions{
        SeverityFilter: []string{"CRITICAL", "HIGH"},
        EnableCache:    true,
        CacheDir:       ".tflint-cache",
        LogLevel:       "info",
        MaxWorkers:     10,
    }
    
    // Scan directory
    result, err := linter.Scan("./terraform", options)
    if err != nil {
        log.Fatal(err)
    }
    
    // Process results
    fmt.Printf("Found %d issues\n", len(result.Issues))
    fmt.Printf("Scanned %d files\n", result.FilesScanned)
    fmt.Printf("Duration: %s\n", result.Duration)
    fmt.Printf("Cache hit rate: %.2f%%\n", result.CacheHitRate)
    
    // Print issues
    for _, issue := range result.Issues {
        fmt.Printf("[%s] %s: %s (line %d)\n", 
            issue.Severity, issue.Rule, issue.Message, issue.Line)
    }
}
```

### Integrating with CI/CD

```go
package main

import (
    "encoding/json"
    "os"
    
    "github.com/heyimusa/go-terraform-linter/internal/linter"
    "github.com/heyimusa/go-terraform-linter/internal/report"
)

func main() {
    // Create linter
    linter := linter.NewLinter()
    
    // Scan with CI-friendly options
    options := &linter.ScanOptions{
        SeverityFilter: []string{"CRITICAL", "HIGH"},
        EnableCache:    false, // Disable cache in CI
        LogLevel:       "warn",
    }
    
    result, err := linter.Scan("./terraform", options)
    if err != nil {
        os.Exit(1)
    }
    
    // Generate SARIF report for GitHub
    reportConfig := &report.ReportConfig{
        Format:     "sarif",
        OutputFile: "security-results.sarif",
    }
    
    reportGen, err := report.NewReport(reportConfig)
    if err != nil {
        os.Exit(1)
    }
    
    reportData, err := reportGen.Generate(result, "sarif")
    if err != nil {
        os.Exit(1)
    }
    
    // Write report
    err = os.WriteFile("security-results.sarif", reportData, 0644)
    if err != nil {
        os.Exit(1)
    }
    
    // Exit with error code if critical issues found
    for _, issue := range result.Issues {
        if issue.Severity == "CRITICAL" {
            os.Exit(1)
        }
    }
}
```

### Custom Validation Rule

```go
package custom

import (
    "github.com/heyimusa/go-terraform-linter/internal/types"
    "github.com/heyimusa/go-terraform-linter/internal/validation"
)

type EnvironmentValidationRule struct{}

func (r *EnvironmentValidationRule) GetName() string {
    return "ENVIRONMENT_VALIDATION"
}

func (r *EnvironmentValidationRule) Validate(block *types.Block, issue *types.Issue) bool {
    // Skip validation for development environment
    if block.Type == "variable" && block.Labels[0] == "environment" {
        if attr, exists := block.Attributes["default"]; exists {
            if attr.RawValue == "dev" {
                return false // Don't validate in dev environment
            }
        }
    }
    return true
}

func (r *EnvironmentValidationRule) GetConfidence(block *types.Block, issue *types.Issue) int {
    // Reduce confidence for certain environments
    if block.Type == "variable" && block.Labels[0] == "environment" {
        if attr, exists := block.Attributes["default"]; exists {
            if attr.RawValue == "staging" {
                return 75 // Lower confidence for staging
            }
        }
    }
    return 95 // High confidence for production
}
```

## Error Handling 🚨

### Common Errors

```go
// Parser errors
type ParseError struct {
    File    string
    Line    int
    Column  int
    Message string
}

// Rule errors
type RuleError struct {
    Rule    string
    Message string
    Cause   error
}

// Cache errors
type CacheError struct {
    Operation string
    Message   string
    Cause     error
}

// Validation errors
type ValidationError struct {
    Rule    string
    Message string
    Block   *types.Block
}
```

### Error Handling Best Practices

```go
// Handle errors gracefully
func handleError(err error) {
    switch e := err.(type) {
    case *ParseError:
        logger.Warn("Parse error", "file", e.File, "line", e.Line, "message", e.Message)
    case *RuleError:
        logger.Error("Rule error", "rule", e.Rule, "message", e.Message)
    case *CacheError:
        logger.Warn("Cache error", "operation", e.Operation, "message", e.Message)
    default:
        logger.Error("Unknown error", "error", err.Error())
    }
}
```

## Performance Considerations ⚡

### Memory Management

```go
// Use streaming for large files
func processLargeFile(filePath string) error {
    file, err := os.Open(filePath)
    if err != nil {
        return err
    }
    defer file.Close()
    
    // Process in chunks
    buffer := make([]byte, 1024*1024) // 1MB chunks
    for {
        n, err := file.Read(buffer)
        if n == 0 {
            break
        }
        if err != nil {
            return err
        }
        // Process chunk
    }
    return nil
}
```

### Concurrency

```go
// Use worker pools for parallel processing
func processFilesConcurrently(files []string, maxWorkers int) {
    semaphore := make(chan struct{}, maxWorkers)
    var wg sync.WaitGroup
    
    for _, file := range files {
        wg.Add(1)
        go func(f string) {
            defer wg.Done()
            semaphore <- struct{}{}
            defer func() { <-semaphore }()
            
            // Process file
        }(file)
    }
    
    wg.Wait()
}
```

## Testing 🧪

### Unit Testing

```go
func TestCustomRule(t *testing.T) {
    tests := []struct {
        name     string
        config   string
        expected []types.Issue
    }{
        // Test cases
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            config, err := parser.ParseString(tt.config)
            assert.NoError(t, err)
            
            rule := &CustomSecurityRule{}
            issues := rule.Check(config)
            
            assert.Equal(t, tt.expected, issues)
        })
    }
}
```

### Integration Testing

```go
func TestLinterIntegration(t *testing.T) {
    // Create temporary directory with test files
    tempDir := t.TempDir()
    
    // Write test Terraform files
    testFiles := map[string]string{
        "main.tf": `resource "aws_s3_bucket" "test" { bucket = "test" }`,
        "variables.tf": `variable "test" { default = "value" }`,
    }
    
    for name, content := range testFiles {
        err := os.WriteFile(filepath.Join(tempDir, name), []byte(content), 0644)
        assert.NoError(t, err)
    }
    
    // Run linter
    linter := linter.NewLinter()
    result, err := linter.Scan(tempDir, &linter.ScanOptions{})
    
    assert.NoError(t, err)
    assert.NotNil(t, result)
    assert.Greater(t, result.FilesScanned, 0)
}
```

---

This API documentation provides comprehensive coverage of all interfaces, types, and functions available in the Go Terraform Linter. For additional examples and use cases, refer to the test files and examples directory.