# 🛠️ Development Guide

This guide covers how to contribute to the Go Terraform Linter project, including setup, development workflow, and best practices.

## 🎯 **v2.0 Development Standards**
- **Go Version**: 1.21+ required (upgraded from 1.18)
- **Test Coverage**: 70%+ maintained across all components
- **Rule Count**: 100+ comprehensive security rules
- **Quality Gates**: All tests must pass, no linter errors

## 📋 Table of Contents

- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Project Structure](#project-structure)
- [Development Workflow](#development-workflow)
- [Testing](#testing)
- [Adding New Rules](#adding-new-rules)
- [Code Style](#code-style)
- [Contributing](#contributing)

## 🚀 Getting Started

### Prerequisites
- **Go**: Version 1.21 or higher (required for v2.0+)
- **Git**: For version control
- **Make**: For build automation (optional)
- **Docker**: For containerized development (optional)
- **Test Coverage Tools**: For maintaining our 70%+ coverage standard

### Fork and Clone
```bash
# Fork the repository on GitHub, then clone your fork
git clone https://github.com/YOUR_USERNAME/go-terraform-linter.git
cd go-terraform-linter

# Add upstream remote
git remote add upstream https://github.com/heyimusa/go-terraform-linter.git
```

### Initial Setup
```bash
# Install dependencies
go mod download

# Run tests to verify setup
go test ./...

# Build the project
go build -o terraform-linter ./cmd/linter

# Verify the build
./terraform-linter --help
```

## 🔧 Development Environment

### IDE Setup

#### VS Code
Recommended extensions:
- Go (official Go extension)
- Go Test Explorer
- GitLens
- YAML
- Terraform

Settings (`.vscode/settings.json`):
```json
{
  "go.testFlags": ["-v"],
  "go.coverOnSave": true,
  "go.coverageDecorator": "gutter",
  "go.lintTool": "golangci-lint",
  "go.formatTool": "goimports"
}
```

#### GoLand/IntelliJ
- Enable Go modules support
- Configure code style to use gofmt
- Set up run configurations for tests

### Development Tools
```bash
# Install development tools
go install golang.org/x/tools/cmd/goimports@latest
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install github.com/securecodewarrior/sast-scan@latest

# Install pre-commit hooks (optional)
pip install pre-commit
pre-commit install
```

### Environment Variables
```bash
# Development environment
export GO_ENV=development
export TF_LINTER_DEBUG=true
export TF_LINTER_LOG_LEVEL=debug

# Testing
export TF_LINTER_TEST_TIMEOUT=30s
export TF_LINTER_CACHE_DISABLED=true
```

## 📁 Project Structure

```
go-terraform-linter/
├── cmd/
│   └── linter/           # CLI application entry point
│       ├── main.go
│       └── main_test.go
├── internal/
│   ├── cache/            # Caching system
│   │   ├── cache.go
│   │   └── cache_test.go
│   ├── config/           # Configuration management
│   │   ├── config.go
│   │   └── config_test.go
│   ├── linter/           # Core linting logic
│   │   ├── linter.go
│   │   ├── parser.go
│   │   └── integration_test.go
│   ├── logger/           # Logging utilities
│   │   ├── logger.go
│   │   └── logger_test.go
│   ├── report/           # Report generation
│   │   ├── report.go
│   │   └── report_test.go
│   ├── rules/            # Rule definitions and engine
│   │   ├── engine/
│   │   ├── aws/
│   │   ├── azure/
│   │   ├── gcp/
│   │   ├── kubernetes/
│   │   └── registry/
│   ├── types/            # Common types and interfaces
│   │   ├── types.go
│   │   └── types_test.go
│   └── validation/       # Issue validation
│       ├── validator.go
│       └── validator_test.go
├── examples/             # Example configurations
├── docs/                 # Documentation
├── .github/              # GitHub workflows
├── scripts/              # Build and utility scripts
└── tests/                # Integration tests
    ├── fixtures/         # Test fixtures
    └── testdata/         # Test data
```

### Key Components

#### Core Types (`internal/types/`)
```go
// Issue represents a linting issue
type Issue struct {
    Rule        string    `json:"rule"`
    Severity    string    `json:"severity"`
    Message     string    `json:"message"`
    File        string    `json:"file"`
    Line        int       `json:"line"`
    Column      int       `json:"column"`
    Resource    string    `json:"resource,omitempty"`
    Fix         string    `json:"fix_suggestion,omitempty"`
}

// Rule interface for all linting rules
type Rule interface {
    GetName() string
    Check(block *Block) []Issue
}
```

#### Rule Engine (`internal/rules/engine/`)
```go
// Engine manages and executes rules
type Engine struct {
    rules    []Rule
    config   *config.Config
    logger   *logger.Logger
}

func (e *Engine) RunRules(blocks []*types.Block) []types.Issue
```

#### Parser (`internal/linter/parser.go`)
```go
// Parser extracts Terraform configuration
type Parser struct {
    logger *logger.Logger
}

func (p *Parser) ParseFile(filename string) ([]*types.Block, error)
```

## 🔄 Development Workflow

### Branch Strategy
We use GitHub Flow:
1. Create feature branch from `main`
2. Make changes and commit
3. Push branch and create Pull Request
4. Code review and merge

### Making Changes
```bash
# Create feature branch
git checkout -b feature/new-aws-rule

# Make your changes
# ... edit files ...

# Run tests
go test ./...

# Run linter
golangci-lint run

# Commit changes
git add .
git commit -m "feat: add new AWS S3 encryption rule"

# Push branch
git push origin feature/new-aws-rule
```

### Commit Messages
We follow Conventional Commits:
- `feat:` New features
- `fix:` Bug fixes
- `docs:` Documentation changes
- `test:` Test additions/changes
- `refactor:` Code refactoring
- `perf:` Performance improvements
- `chore:` Maintenance tasks

Examples:
```
feat: add AWS RDS encryption rule
fix: handle nil pointer in parser
docs: update installation guide
test: add integration tests for Azure rules
```

## 🧪 Testing

### Test Structure
```
tests/
├── unit/              # Unit tests (alongside source files)
├── integration/       # Integration tests
├── fixtures/          # Test fixtures
│   ├── aws/
│   ├── azure/
│   ├── gcp/
│   └── kubernetes/
└── testdata/          # Test data files
```

### Running Tests
```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run tests with detailed coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Run specific test package
go test ./internal/rules/aws/...

# Run specific test
go test -run TestS3BucketPublicAccess ./internal/rules/aws/

# Run tests with race detection
go test -race ./...

# Run benchmarks
go test -bench=. ./...
```

### Writing Tests

#### Unit Tests
```go
func TestS3BucketPublicAccessRule(t *testing.T) {
    rule := &S3BucketPublicAccessRule{}
    
    tests := []struct {
        name     string
        block    *types.Block
        expected int // number of issues
    }{
        {
            name: "bucket without public access block",
            block: &types.Block{
                Type: "resource",
                Labels: []string{"aws_s3_bucket", "test"},
                Attributes: map[string]*types.Attribute{
                    "bucket": {Value: "test-bucket"},
                },
            },
            expected: 1,
        },
        {
            name: "bucket with public access block",
            block: &types.Block{
                Type: "resource",
                Labels: []string{"aws_s3_bucket_public_access_block", "test"},
                Attributes: map[string]*types.Attribute{
                    "bucket": {Value: "test-bucket"},
                    "block_public_acls": {Value: true},
                },
            },
            expected: 0,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            issues := rule.Check(tt.block)
            assert.Len(t, issues, tt.expected)
        })
    }
}
```

#### Integration Tests
```go
func TestLinterIntegration(t *testing.T) {
    tmpDir := t.TempDir()
    
    // Create test Terraform file
    tfContent := `
resource "aws_s3_bucket" "test" {
  bucket = "test-bucket"
}
`
    err := os.WriteFile(filepath.Join(tmpDir, "main.tf"), []byte(tfContent), 0644)
    require.NoError(t, err)
    
    // Run linter
    cfg := &config.Config{
        Paths: []string{tmpDir},
        Severity: "low",
    }
    
    linter := linter.New(cfg)
    issues, err := linter.Run()
    require.NoError(t, err)
    
    // Verify results
    assert.NotEmpty(t, issues)
    assert.Equal(t, "aws-s3-bucket-public-access-block", issues[0].Rule)
}
```

### Test Fixtures
Create realistic test fixtures in `tests/fixtures/`:

```hcl
# tests/fixtures/aws/s3-insecure.tf
resource "aws_s3_bucket" "insecure" {
  bucket = "my-insecure-bucket"
  acl    = "public-read"
}

# tests/fixtures/aws/s3-secure.tf
resource "aws_s3_bucket" "secure" {
  bucket = "my-secure-bucket"
}

resource "aws_s3_bucket_public_access_block" "secure" {
  bucket = aws_s3_bucket.secure.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

## ➕ Adding New Rules

### Rule Implementation
1. Create rule file in appropriate provider directory
2. Implement the Rule interface
3. Add comprehensive tests
4. Update documentation

#### Example: New AWS Rule
```go
// internal/rules/aws/s3_bucket_mfa_delete.go
package aws

import (
    "github.com/heyimusa/go-terraform-linter/internal/types"
)

type S3BucketMFADeleteRule struct{}

func (r *S3BucketMFADeleteRule) GetName() string {
    return "aws-s3-bucket-mfa-delete"
}

func (r *S3BucketMFADeleteRule) GetDescription() string {
    return "Ensures S3 buckets have MFA delete enabled"
}

func (r *S3BucketMFADeleteRule) GetSeverity() string {
    return "medium"
}

func (r *S3BucketMFADeleteRule) Check(block *types.Block) []types.Issue {
    if !r.isS3Bucket(block) {
        return nil
    }
    
    // Check for MFA delete configuration
    if !r.hasMFADelete(block) {
        return []types.Issue{
            {
                Rule:     r.GetName(),
                Severity: r.GetSeverity(),
                Message:  "S3 bucket should have MFA delete enabled for enhanced security",
                File:     block.File,
                Line:     block.Line,
                Resource: block.GetResourceName(),
                Fix:      "Add MFA delete configuration to the bucket versioning block",
            },
        }
    }
    
    return nil
}

func (r *S3BucketMFADeleteRule) isS3Bucket(block *types.Block) bool {
    return block.Type == "resource" && 
           len(block.Labels) >= 2 && 
           block.Labels[0] == "aws_s3_bucket"
}

func (r *S3BucketMFADeleteRule) hasMFADelete(block *types.Block) bool {
    // Implementation logic here
    return false
}
```

#### Rule Tests
```go
// internal/rules/aws/s3_bucket_mfa_delete_test.go
func TestS3BucketMFADeleteRule(t *testing.T) {
    rule := &S3BucketMFADeleteRule{}
    
    tests := []struct {
        name     string
        block    *types.Block
        expected int
    }{
        {
            name: "S3 bucket without MFA delete",
            block: &types.Block{
                Type: "resource",
                Labels: []string{"aws_s3_bucket", "test"},
                // ... test data
            },
            expected: 1,
        },
        // ... more test cases
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            issues := rule.Check(tt.block)
            assert.Len(t, issues, tt.expected)
            
            if tt.expected > 0 {
                assert.Equal(t, "aws-s3-bucket-mfa-delete", issues[0].Rule)
                assert.Equal(t, "medium", issues[0].Severity)
            }
        })
    }
}
```

### Rule Registration
Add new rules to the registry:

```go
// internal/rules/registry/aws.go
func RegisterAWSRules(registry *Registry) {
    registry.Register(&aws.S3BucketPublicAccessRule{})
    registry.Register(&aws.S3BucketEncryptionRule{})
    registry.Register(&aws.S3BucketMFADeleteRule{}) // New rule
    // ... other rules
}
```

### Rule Documentation
Update `docs/RULES.md` with the new rule:

```markdown
#### aws-s3-bucket-mfa-delete
- **Severity**: 🟡 Medium
- **Category**: Security
- **Status**: ✅ Enabled
- **Description**: Ensures S3 buckets have MFA delete enabled
- **Risk**: Accidental or malicious deletion of objects
```

## 🎨 Code Style

### Go Style Guidelines
- Follow official Go style guide
- Use `gofmt` for formatting
- Use `goimports` for import organization
- Follow Go naming conventions

### Linting
We use `golangci-lint` with this configuration:

```yaml
# .golangci.yml
linters:
  enable:
    - gofmt
    - goimports
    - govet
    - errcheck
    - staticcheck
    - unused
    - gosimple
    - ineffassign
    - typecheck
    - misspell
    - gocritic

linters-settings:
  gocritic:
    enabled-tags:
      - performance
      - style
      - experimental
```

### Code Organization
```go
// Package structure
package aws

import (
    // Standard library first
    "fmt"
    "strings"
    
    // Third-party packages
    "github.com/hashicorp/hcl/v2"
    
    // Internal packages
    "github.com/heyimusa/go-terraform-linter/internal/types"
)

// Constants
const (
    DefaultSeverity = "medium"
    MaxIssuesPerRule = 100
)

// Types
type RuleConfig struct {
    Enabled   bool     `yaml:"enabled"`
    Severity  string   `yaml:"severity"`
    Exceptions []string `yaml:"exceptions"`
}

// Functions
func NewRule(config *RuleConfig) *Rule {
    // Implementation
}
```

### Error Handling
```go
// Preferred error handling
func (r *Rule) validateConfig() error {
    if r.config == nil {
        return fmt.Errorf("rule config is nil")
    }
    
    if r.config.Severity == "" {
        return fmt.Errorf("severity cannot be empty")
    }
    
    return nil
}

// Use errors.Is and errors.As for error checking
if errors.Is(err, ErrConfigNotFound) {
    // Handle specific error
}
```

### Testing Best Practices
```go
// Use table-driven tests
func TestRuleValidation(t *testing.T) {
    tests := []struct {
        name    string
        config  *RuleConfig
        wantErr bool
    }{
        {
            name:    "valid config",
            config:  &RuleConfig{Enabled: true, Severity: "high"},
            wantErr: false,
        },
        {
            name:    "invalid severity",
            config:  &RuleConfig{Enabled: true, Severity: ""},
            wantErr: true,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            rule := &Rule{config: tt.config}
            err := rule.validateConfig()
            
            if tt.wantErr {
                assert.Error(t, err)
            } else {
                assert.NoError(t, err)
            }
        })
    }
}
```

## 🤝 Contributing

### Pull Request Process
1. **Fork** the repository
2. **Create** a feature branch
3. **Make** your changes
4. **Write** tests
5. **Update** documentation
6. **Submit** pull request

### Pull Request Checklist
- [ ] Code follows project style guidelines
- [ ] Tests pass locally
- [ ] New tests added for new functionality
- [ ] Documentation updated
- [ ] Commit messages follow conventional format
- [ ] No breaking changes (or clearly documented)

### Code Review Guidelines
- Be respectful and constructive
- Focus on code, not the person
- Explain the "why" behind suggestions
- Approve when ready, request changes when needed

### Release Process
1. Update version in `cmd/linter/main.go`
2. Update `CHANGELOG.md`
3. Create release PR
4. Tag release after merge
5. GitHub Actions handles the rest

---

**Additional Resources**:
- [Go Documentation](https://golang.org/doc/)
- [Terraform Plugin Development](https://www.terraform.io/docs/extend/writing-custom-providers.html)
- [HCL Parsing](https://github.com/hashicorp/hcl)
- [Project Issues](https://github.com/heyimusa/go-terraform-linter/issues) 