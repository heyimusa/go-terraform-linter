# 📡 API Reference

This guide covers the programmatic API for integrating the Go Terraform Linter into your applications.

## 📋 Table of Contents

- [Package Overview](#package-overview)
- [Core Interfaces](#core-interfaces)
- [Linter API](#linter-api)
- [Configuration API](#configuration-api)
- [Rules API](#rules-api)
- [Report API](#report-api)
- [Examples](#examples)
- [Error Handling](#error-handling)

## 📦 Package Overview

### Import Paths
```go
import (
    "github.com/heyimusa/go-terraform-linter/internal/linter"
    "github.com/heyimusa/go-terraform-linter/internal/config"
    "github.com/heyimusa/go-terraform-linter/internal/rules"
    "github.com/heyimusa/go-terraform-linter/internal/types"
    "github.com/heyimusa/go-terraform-linter/internal/report"
)
```

### Module Structure
- `internal/linter`: Core linting functionality
- `internal/config`: Configuration management
- `internal/rules`: Rule definitions and engine
- `internal/types`: Common types and interfaces
- `internal/report`: Report generation and formatting

## 🔌 Core Interfaces

### Rule Interface
```go
type Rule interface {
    GetName() string
    Check(block *Block) []Issue
}

// Advanced rule interface with metadata
type AdvancedRule interface {
    Rule
    GetDescription() string
    GetSeverity() string
    GetCategory() string
    GetProvider() string
    GetTags() []string
    GetVersion() string
}
```

### Block Interface
```go
type Block struct {
    Type       string                    `json:"type"`
    Labels     []string                  `json:"labels"`
    Attributes map[string]*Attribute     `json:"attributes"`
    Blocks     []*Block                  `json:"blocks"`
    File       string                    `json:"file"`
    Line       int                       `json:"line"`
    Column     int                       `json:"column"`
}

func (b *Block) GetAttribute(name string) (*Attribute, bool)
func (b *Block) GetBlock(blockType string) (*Block, bool)
func (b *Block) GetBlocks(blockType string) []*Block
func (b *Block) GetResourceName() string
func (b *Block) HasAttribute(name string) bool
```

### Issue Interface
```go
type Issue struct {
    Rule         string    `json:"rule"`
    Severity     string    `json:"severity"`
    Message      string    `json:"message"`
    File         string    `json:"file"`
    Line         int       `json:"line"`
    Column       int       `json:"column"`
    Resource     string    `json:"resource,omitempty"`
    Fix          string    `json:"fix_suggestion,omitempty"`
    Confidence   float64   `json:"confidence,omitempty"`
    Category     string    `json:"category,omitempty"`
    Provider     string    `json:"provider,omitempty"`
    Timestamp    time.Time `json:"timestamp"`
}
```

## 🔍 Linter API

### Linter Creation
```go
package main

import (
    "github.com/heyimusa/go-terraform-linter/internal/linter"
    "github.com/heyimusa/go-terraform-linter/internal/config"
)

func main() {
    // Create configuration
    cfg := &config.Config{
        Paths:    []string{"."},
        Severity: "medium",
        Format:   "json",
        Parallel: 4,
    }
    
    // Create linter instance
    l := linter.New(cfg)
    
    // Run linting
    issues, err := l.Run()
    if err != nil {
        panic(err)
    }
    
    // Process results
    for _, issue := range issues {
        fmt.Printf("Found issue: %s in %s:%d\n", 
            issue.Rule, issue.File, issue.Line)
    }
}
```

### Linter Methods
```go
type Linter struct {
    config *config.Config
    engine *rules.Engine
    parser *Parser
    logger *logger.Logger
}

// Create new linter instance
func New(cfg *config.Config) *Linter

// Run linting on configured paths
func (l *Linter) Run() ([]types.Issue, error)

// Run linting on specific files
func (l *Linter) RunOnFiles(files []string) ([]types.Issue, error)

// Run linting on parsed blocks
func (l *Linter) RunOnBlocks(blocks []*types.Block) []types.Issue

// Parse Terraform files
func (l *Linter) ParseFiles(files []string) ([]*types.Block, error)

// Get linter statistics
func (l *Linter) GetStats() *Stats
```

### Linter Configuration
```go
type Config struct {
    // File patterns
    Paths    []string `yaml:"paths"`
    Include  []string `yaml:"include"`
    Exclude  []string `yaml:"exclude"`
    
    // Filtering
    Severity string   `yaml:"severity"`
    Rules    []string `yaml:"rules"`
    
    // Performance
    Parallel int      `yaml:"parallel"`
    Timeout  int      `yaml:"timeout"`
    
    // Output
    Format   string   `yaml:"format"`
    Output   string   `yaml:"output"`
    Verbose  bool     `yaml:"verbose"`
    
    // Caching
    Cache    bool     `yaml:"cache"`
    CacheDir string   `yaml:"cache_dir"`
    CacheTTL string   `yaml:"cache_ttl"`
}

// Load configuration from file
func LoadConfig(path string) (*Config, error)

// Validate configuration
func (c *Config) Validate() error

// Merge configurations
func (c *Config) Merge(other *Config) *Config
```

## ⚙️ Configuration API

### Configuration Management
```go
package config

// Configuration loader
type Loader struct {
    searchPaths []string
    validators  []Validator
}

func NewLoader() *Loader
func (l *Loader) AddSearchPath(path string)
func (l *Loader) Load() (*Config, error)

// Configuration validation
type Validator interface {
    Validate(config *Config) error
}

// Built-in validators
func NewPathValidator() Validator
func NewRuleValidator() Validator
func NewSeverityValidator() Validator
```

### Environment Integration
```go
// Load configuration from environment variables
func LoadFromEnvironment() (*Config, error)

// Environment variable mapping
var EnvMapping = map[string]string{
    "TF_LINTER_SEVERITY": "severity",
    "TF_LINTER_FORMAT":   "format",
    "TF_LINTER_PARALLEL": "parallel",
    "TF_LINTER_VERBOSE":  "verbose",
}

// Override config with environment variables
func (c *Config) ApplyEnvironment() error
```

## 📋 Rules API

### Rule Engine
```go
package rules

type Engine struct {
    rules    []types.Rule
    config   *config.Config
    registry *Registry
}

// Create new rule engine
func NewEngine(cfg *config.Config) *Engine

// Register rules
func (e *Engine) RegisterRule(rule types.Rule) error
func (e *Engine) RegisterRules(rules []types.Rule) error

// Execute rules
func (e *Engine) RunRules(blocks []*types.Block) []types.Issue
func (e *Engine) RunRule(rule types.Rule, blocks []*types.Block) []types.Issue

// Rule management
func (e *Engine) GetRules() []types.Rule
func (e *Engine) GetRule(name string) (types.Rule, error)
func (e *Engine) EnableRule(name string) error
func (e *Engine) DisableRule(name string) error
```

### Rule Registry
```go
type Registry struct {
    rules    map[string]types.Rule
    metadata map[string]*RuleMetadata
}

func NewRegistry() *Registry

// Rule registration
func (r *Registry) Register(rule types.Rule) error
func (r *Registry) RegisterWithMetadata(rule types.Rule, meta *RuleMetadata) error

// Rule discovery
func (r *Registry) GetRule(name string) (types.Rule, error)
func (r *Registry) GetRules() []types.Rule
func (r *Registry) GetRulesByProvider(provider string) []types.Rule
func (r *Registry) GetRulesByCategory(category string) []types.Rule
func (r *Registry) GetRulesBySeverity(severity string) []types.Rule

// Rule metadata
type RuleMetadata struct {
    Name         string   `json:"name"`
    Description  string   `json:"description"`
    Provider     string   `json:"provider"`
    Category     string   `json:"category"`
    Severity     string   `json:"severity"`
    Tags         []string `json:"tags"`
    Version      string   `json:"version"`
    Enabled      bool     `json:"enabled"`
}
```

### Custom Rule Creation
```go
// Simple rule implementation
type CustomRule struct {
    name        string
    description string
    severity    string
    checkFunc   func(*types.Block) []types.Issue
}

func NewCustomRule(name, description, severity string, 
                   checkFunc func(*types.Block) []types.Issue) *CustomRule {
    return &CustomRule{
        name:        name,
        description: description,
        severity:    severity,
        checkFunc:   checkFunc,
    }
}

func (r *CustomRule) GetName() string {
    return r.name
}

func (r *CustomRule) Check(block *types.Block) []types.Issue {
    return r.checkFunc(block)
}

// Rule builder for fluent API
type RuleBuilder struct {
    rule *CustomRule
}

func NewRuleBuilder() *RuleBuilder
func (rb *RuleBuilder) Name(name string) *RuleBuilder
func (rb *RuleBuilder) Description(desc string) *RuleBuilder
func (rb *RuleBuilder) Severity(severity string) *RuleBuilder
func (rb *RuleBuilder) Check(checkFunc func(*types.Block) []types.Issue) *RuleBuilder
func (rb *RuleBuilder) Build() types.Rule
```

## 📊 Report API

### Report Generation
```go
package report

type Report struct {
    Issues    []types.Issue `json:"issues"`
    Summary   *Summary      `json:"summary"`
    Metadata  *Metadata     `json:"metadata"`
    Timestamp time.Time     `json:"timestamp"`
}

// Create new report
func NewReport() *Report

// Add issues to report
func (r *Report) AddIssue(issue types.Issue)
func (r *Report) AddIssues(issues []types.Issue)

// Generate summary
func (r *Report) GenerateSummary() *Summary

// Report formatting
func (r *Report) Format(format string) ([]byte, error)
func (r *Report) FormatJSON() ([]byte, error)
func (r *Report) FormatSARIF() ([]byte, error)
func (r *Report) FormatHTML() ([]byte, error)
func (r *Report) FormatText() ([]byte, error)

// Save report
func (r *Report) SaveToFile(filename string, format string) error
```

### Report Summary
```go
type Summary struct {
    Total      int                    `json:"total"`
    BySeverity map[string]int         `json:"by_severity"`
    ByProvider map[string]int         `json:"by_provider"`
    ByCategory map[string]int         `json:"by_category"`
    ByFile     map[string]int         `json:"by_file"`
    Rules      map[string]int         `json:"rules"`
}

func (s *Summary) HasIssues() bool
func (s *Summary) GetHighestSeverity() string
func (s *Summary) GetMostFrequentRule() string
```

### Custom Formatters
```go
// Formatter interface
type Formatter interface {
    Format(report *Report) ([]byte, error)
    GetMimeType() string
    GetFileExtension() string
}

// Register custom formatter
func RegisterFormatter(name string, formatter Formatter) error

// Example custom formatter
type CSVFormatter struct{}

func (f *CSVFormatter) Format(report *Report) ([]byte, error) {
    var buf bytes.Buffer
    writer := csv.NewWriter(&buf)
    
    // Write CSV header
    writer.Write([]string{"Rule", "Severity", "File", "Line", "Message"})
    
    // Write issues
    for _, issue := range report.Issues {
        writer.Write([]string{
            issue.Rule,
            issue.Severity,
            issue.File,
            strconv.Itoa(issue.Line),
            issue.Message,
        })
    }
    
    writer.Flush()
    return buf.Bytes(), nil
}

func (f *CSVFormatter) GetMimeType() string { return "text/csv" }
func (f *CSVFormatter) GetFileExtension() string { return ".csv" }
```

## 💡 Examples

### Basic Usage
```go
package main

import (
    "fmt"
    "log"
    
    "github.com/heyimusa/go-terraform-linter/internal/linter"
    "github.com/heyimusa/go-terraform-linter/internal/config"
)

func main() {
    // Simple linting
    cfg := &config.Config{
        Paths:    []string{"./terraform"},
        Severity: "medium",
    }
    
    l := linter.New(cfg)
    issues, err := l.Run()
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Found %d issues\n", len(issues))
}
```

### Advanced Configuration
```go
func advancedExample() {
    cfg := &config.Config{
        Paths:    []string{"./infrastructure"},
        Include:  []string{"**/*.tf", "**/*.tfvars"},
        Exclude:  []string{"**/test/**", "**/.terraform/**"},
        Severity: "low",
        Parallel: 8,
        Cache:    true,
        CacheDir: ".terraform-linter-cache",
        Rules: []string{
            "aws-s3-*",
            "aws-ec2-security-group-*",
            "security-*",
        },
    }
    
    l := linter.New(cfg)
    issues, err := l.Run()
    if err != nil {
        log.Fatal(err)
    }
    
    // Generate report
    report := report.NewReport()
    report.AddIssues(issues)
    
    // Save as JSON
    jsonData, _ := report.FormatJSON()
    report.SaveToFile("security-report.json", "json")
    
    // Save as HTML
    htmlData, _ := report.FormatHTML()
    report.SaveToFile("security-report.html", "html")
}
```

### Custom Rule Integration
```go
func customRuleExample() {
    // Create custom rule
    customRule := rules.NewCustomRule(
        "company-tagging-standard",
        "Ensures all resources have required company tags",
        "medium",
        func(block *types.Block) []types.Issue {
            if block.Type != "resource" {
                return nil
            }
            
            tags, exists := block.GetAttribute("tags")
            if !exists {
                return []types.Issue{
                    {
                        Rule:     "company-tagging-standard",
                        Severity: "medium",
                        Message:  "Resource missing required tags",
                        File:     block.File,
                        Line:     block.Line,
                        Resource: block.GetResourceName(),
                    },
                }
            }
            
            // Check for required tags
            requiredTags := []string{"Environment", "Owner", "Project"}
            for _, tag := range requiredTags {
                if !hasTag(tags, tag) {
                    return []types.Issue{
                        {
                            Rule:     "company-tagging-standard",
                            Severity: "medium",
                            Message:  fmt.Sprintf("Missing required tag: %s", tag),
                            File:     block.File,
                            Line:     block.Line,
                            Resource: block.GetResourceName(),
                        },
                    }
                }
            }
            
            return nil
        },
    )
    
    // Register custom rule
    cfg := &config.Config{Paths: []string{"."}}
    l := linter.New(cfg)
    l.RegisterRule(customRule)
    
    issues, err := l.Run()
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Found %d issues with custom rule\n", len(issues))
}
```

### Streaming Results
```go
func streamingExample() {
    cfg := &config.Config{Paths: []string{"./large-terraform-project"}}
    l := linter.New(cfg)
    
    // Create channel for streaming results
    issuesChan := make(chan types.Issue, 100)
    errorsChan := make(chan error, 10)
    
    // Start linting in goroutine
    go func() {
        defer close(issuesChan)
        defer close(errorsChan)
        
        err := l.RunWithCallback(func(issue types.Issue) {
            issuesChan <- issue
        })
        
        if err != nil {
            errorsChan <- err
        }
    }()
    
    // Process results as they come
    for {
        select {
        case issue, ok := <-issuesChan:
            if !ok {
                return // Done
            }
            fmt.Printf("Issue: %s in %s:%d\n", issue.Rule, issue.File, issue.Line)
            
        case err := <-errorsChan:
            log.Printf("Error: %v\n", err)
            
        case <-time.After(30 * time.Second):
            log.Println("Timeout waiting for results")
            return
        }
    }
}
```

### Integration with CI/CD
```go
func cicdIntegration() {
    cfg := &config.Config{
        Paths:    []string{os.Getenv("TERRAFORM_DIR")},
        Severity: os.Getenv("SEVERITY_THRESHOLD"),
        Format:   "sarif",
    }
    
    l := linter.New(cfg)
    issues, err := l.Run()
    if err != nil {
        log.Fatal(err)
    }
    
    // Generate SARIF report for GitHub
    report := report.NewReport()
    report.AddIssues(issues)
    
    sarifData, err := report.FormatSARIF()
    if err != nil {
        log.Fatal(err)
    }
    
    // Save SARIF file for GitHub Actions
    err = os.WriteFile("results.sarif", sarifData, 0644)
    if err != nil {
        log.Fatal(err)
    }
    
    // Exit with error code if critical issues found
    summary := report.GenerateSummary()
    if summary.BySeverity["critical"] > 0 {
        os.Exit(1)
    }
}
```

## ❌ Error Handling

### Error Types
```go
// Common error types
var (
    ErrConfigNotFound   = errors.New("configuration file not found")
    ErrInvalidConfig    = errors.New("invalid configuration")
    ErrParseError       = errors.New("failed to parse terraform file")
    ErrRuleNotFound     = errors.New("rule not found")
    ErrTimeout          = errors.New("operation timed out")
    ErrPermissionDenied = errors.New("permission denied")
)

// Error with context
type LinterError struct {
    Op   string // Operation that failed
    Path string // File path (if applicable)
    Err  error  // Underlying error
}

func (e *LinterError) Error() string {
    if e.Path != "" {
        return fmt.Sprintf("%s %s: %v", e.Op, e.Path, e.Err)
    }
    return fmt.Sprintf("%s: %v", e.Op, e.Err)
}

func (e *LinterError) Unwrap() error {
    return e.Err
}
```

### Error Handling Patterns
```go
func handleErrors() {
    cfg := &config.Config{Paths: []string{"./terraform"}}
    l := linter.New(cfg)
    
    issues, err := l.Run()
    if err != nil {
        // Check for specific error types
        var lintErr *LinterError
        if errors.As(err, &lintErr) {
            log.Printf("Linter error in %s: %v", lintErr.Path, lintErr.Err)
        }
        
        // Check for specific errors
        if errors.Is(err, ErrConfigNotFound) {
            log.Println("Configuration file not found, using defaults")
            // Continue with default configuration
        } else if errors.Is(err, ErrParseError) {
            log.Println("Parse error, skipping problematic files")
            // Continue with partial results
        } else {
            log.Fatal(err)
        }
    }
    
    // Process issues...
}
```

### Graceful Degradation
```go
func gracefulDegradation() {
    cfg := &config.Config{Paths: []string{"./terraform"}}
    l := linter.New(cfg)
    
    // Set error handler for non-fatal errors
    l.SetErrorHandler(func(err error) {
        log.Printf("Non-fatal error: %v", err)
    })
    
    // Run with partial results on errors
    issues, err := l.RunWithPartialResults()
    if err != nil {
        log.Printf("Some errors occurred, but got %d results", len(issues))
    }
    
    // Process available results...
}
```

---

**Additional Resources**:
- [Go Documentation](https://pkg.go.dev/github.com/heyimusa/go-terraform-linter)
- [Usage Examples](USAGE.md)
- [Development Guide](DEVELOPMENT.md)
- [Configuration Reference](CONFIGURATION.md) 