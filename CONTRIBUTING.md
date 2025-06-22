# Contributing to Go Terraform Linter 🤝

Thank you for your interest in contributing to Go Terraform Linter! This document provides guidelines and best practices for contributing to the project.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Code Style](#code-style)
- [Testing Guidelines](#testing-guidelines)
- [Adding New Rules](#adding-new-rules)
- [Performance Considerations](#performance-considerations)
- [Pull Request Process](#pull-request-process)
- [Code Review Guidelines](#code-review-guidelines)

## Getting Started 🚀

### Prerequisites

- Go 1.18 or higher
- Git
- Make (optional, for build scripts)

### Fork and Clone

   ```bash
# Fork the repository on GitHub
# Then clone your fork
git clone https://github.com/YOUR_USERNAME/go-terraform-linter.git
cd go-terraform-linter

# Add the upstream remote
git remote add upstream https://github.com/heyimusa/go-terraform-linter.git
```

### Install Dependencies

   ```bash
# Download Go modules
go mod download

# Verify everything works
go test ./... -v
   go build -o tflint cmd/linter/main.go
   ```

## Development Environment 🛠️

### Project Structure

```
go-terraform-linter/
├── cmd/linter/              # CLI entry point
├── internal/
│   ├── linter/             # Core linting engine
│   ├── parser/             # HCL parsing with tests
│   ├── rules/              # Security rules engine
│   │   ├── security/       # Cloud-specific rules
│   │   │   ├── azure.go    # Azure security rules
│   │   │   ├── aws.go      # AWS security rules
│   │   │   └── tests/      # Rule unit tests
│   │   └── custom/         # Custom rule support
│   ├── cache/              # File-based caching
│   ├── logger/             # Structured logging
│   ├── validation/         # Rule validation framework
│   └── types/              # Shared data structures
├── examples/               # Example Terraform files
└── docs/                   # Documentation
```

### Development Workflow

   ```bash
# Create a feature branch
git checkout -b feature/your-feature-name

# Make your changes
# ... edit files ...

# Run tests
go test ./... -v

# Run with coverage
go test ./... -cover

# Build and test locally
go build -o tflint cmd/linter/main.go
./tflint -v examples/

# Commit your changes
git add .
git commit -m "feat: add new security rule for X"

# Push to your fork
git push origin feature/your-feature-name
```

## Code Style 📝

### Go Code Style

- Follow [Effective Go](https://golang.org/doc/effective_go.html)
- Use `gofmt` for formatting
- Follow the existing naming conventions
- Add comments for exported functions and types
- Keep functions focused and small

### Naming Conventions

- **Files**: Use snake_case for test files (e.g., `azure_test.go`)
- **Functions**: Use camelCase for private, PascalCase for exported
- **Variables**: Use camelCase
- **Constants**: Use UPPER_SNAKE_CASE
- **Types**: Use PascalCase

### Example Code Style

```go
// Good
type AzureSecurityRule struct {
    name        string
    description string
    severity    string
}

func (r *AzureSecurityRule) GetName() string {
    return r.name
}

// Bad
type azure_security_rule struct {
    Name        string
    Description string
    Severity    string
}

func (r *azure_security_rule) get_name() string {
    return r.Name
}
```

## Testing Guidelines 🧪

### Test Structure

All new code must include comprehensive tests. Follow this structure:

```go
// internal/rules/security/tests/your_rule_test.go
package tests

import (
    "testing"
    "github.com/stretchr/testify/assert"
    "github.com/heyimusa/go-terraform-linter/internal/parser"
    "github.com/heyimusa/go-terraform-linter/internal/rules/security"
)

func TestYourNewRule(t *testing.T) {
    tests := []struct {
        name     string
        config   string
        expected []types.Issue
    }{
        {
            name: "should detect security issue",
            config: `
                resource "azurerm_virtual_machine" "test" {
                    name = "test-vm"
                    # Your test case here
                }
            `,
            expected: []types.Issue{
                {
                    Rule:     "YOUR_NEW_RULE",
                    Severity: "HIGH",
                    Message:  "Security issue detected",
                    Line:     3,
                },
            },
        },
        {
            name: "should not trigger on valid config",
            config: `
                resource "azurerm_virtual_machine" "test" {
                    name = "test-vm"
                    # Valid configuration
                }
            `,
            expected: []types.Issue{},
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            config, err := parser.ParseString(tt.config)
            assert.NoError(t, err)

            rule := &security.YourNewRule{}
            issues := rule.Check(config)

            assert.Equal(t, tt.expected, issues)
        })
    }
}
```

### Test Best Practices

1. **Use Table-Driven Tests**: Test multiple scenarios in one function
2. **Test Edge Cases**: Invalid inputs, empty configs, malformed HCL
3. **Mock External Dependencies**: Use interfaces for testability
4. **Test Performance**: Add benchmarks for performance-critical code
5. **Use Test Helpers**: Create helper functions for common test setup

### Running Tests

   ```bash
# Run all tests
go test ./... -v

# Run specific test suite
go test ./internal/rules/security/tests/ -v

# Run with coverage
go test ./... -cover

# Run benchmarks
go test ./... -bench=.

# Run tests with race detection
go test ./... -race
   ```

### Test Coverage Requirements

- **Minimum Coverage**: 80% for new code
- **Critical Paths**: 100% coverage for security rules
- **Edge Cases**: Test error conditions and invalid inputs
- **Integration Tests**: Test end-to-end workflows

## Adding New Rules 🔧

### Rule Structure

All security rules must implement the `Rule` interface:

```go
type Rule interface {
    GetName() string
    GetDescription() string
    GetSeverity() string
    Check(config *parser.Config) []types.Issue
}
```

### Example Rule Implementation

```go
// internal/rules/security/azure.go
type AzureNewSecurityRule struct{}

func (r *AzureNewSecurityRule) GetName() string {
    return "AZURE_NEW_SECURITY"
}

func (r *AzureNewSecurityRule) GetDescription() string {
    return "Detects new Azure security misconfiguration"
}

func (r *AzureNewSecurityRule) GetSeverity() string {
    return "HIGH"
}

func (r *AzureNewSecurityRule) Check(config *parser.Config) []types.Issue {
    var issues []types.Issue
    
    for _, block := range config.Blocks {
        // Your detection logic here
        if r.detectIssue(block) {
            issues = append(issues, types.Issue{
                Rule:        r.GetName(),
                Severity:    r.GetSeverity(),
                Message:     "Security issue detected",
                Description: "Detailed description and fix suggestion",
                Line:        block.Range.Start.Line,
                Confidence:  85, // Add confidence score
            })
        }
    }
    
    return issues
}

func (r *AzureNewSecurityRule) detectIssue(block *types.Block) bool {
    // Implementation details
    return false
}
```

### Registering Rules

Add your rule to the appropriate rule engine:

```go
// internal/rules/engine.go
func GetAzureRules() []Rule {
    return []Rule{
        &AzureExposedSecretsRule{},
        &AzureWeakAuthenticationRule{},
        // ... other rules ...
        &AzureNewSecurityRule{}, // Add your rule here
    }
}
```

### Rule Testing

Create comprehensive tests for your rule:

```go
// internal/rules/security/tests/azure_new_security_test.go
func TestAzureNewSecurityRule(t *testing.T) {
    tests := []struct {
        name     string
        config   string
        expected []types.Issue
    }{
        {
            name: "should detect security issue",
            config: `
                resource "azurerm_virtual_machine" "test" {
                    # Your test case
                }
            `,
            expected: []types.Issue{
                {
                    Rule:     "AZURE_NEW_SECURITY",
                    Severity: "HIGH",
                    Line:     2,
                },
            },
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            config, err := parser.ParseString(tt.config)
            assert.NoError(t, err)

            rule := &AzureNewSecurityRule{}
            issues := rule.Check(config)

            assert.Equal(t, tt.expected, issues)
        })
    }
}
```

## Performance Considerations ⚡

### Caching Integration

When adding new rules, consider caching implications:

```go
// Use the cache system for performance
func (r *YourRule) Check(config *parser.Config) []types.Issue {
    // Check cache first
    cacheKey := r.generateCacheKey(config)
    if cached, exists := cache.Get(cacheKey); exists {
        return cached.([]types.Issue)
    }

    // Your rule logic here
    issues := r.performCheck(config)

    // Cache the result
    cache.Set(cacheKey, issues, cache.DefaultExpiration)
    return issues
}
```

### Logging Integration

Add appropriate logging to your rules:

```go
import "github.com/heyimusa/go-terraform-linter/internal/logger"

func (r *YourRule) Check(config *parser.Config) []types.Issue {
    logger.Debug("Starting rule check", "rule", r.GetName(), "blocks", len(config.Blocks))
    
    // Your logic here
    
    logger.Info("Rule check completed", "rule", r.GetName(), "issues", len(issues))
    return issues
}
```

### Validation Integration

Use the validation framework to reduce false positives:

```go
import "github.com/heyimusa/go-terraform-linter/internal/validation"

func (r *YourRule) Check(config *parser.Config) []types.Issue {
    var issues []types.Issue
    
    for _, block := range config.Blocks {
        if r.detectIssue(block) {
            // Validate the issue to reduce false positives
            if validator.ValidateIssue(block, r.GetName()) {
                issues = append(issues, types.Issue{
                    Rule:        r.GetName(),
                    Severity:    r.GetSeverity(),
                    Message:     "Issue detected",
                    Confidence:  validator.GetConfidence(block, r.GetName()),
                })
            }
        }
    }
    
    return issues
}
```

## Pull Request Process 📋

### Before Submitting

1. **Run Tests**: Ensure all tests pass
2. **Check Coverage**: Verify test coverage meets requirements
3. **Format Code**: Run `gofmt` on your changes
4. **Update Documentation**: Update README, CONTRIBUTING, etc.
5. **Test Locally**: Build and test the binary

```bash
# Pre-submission checklist
go test ./... -v
go test ./... -cover
gofmt -w .
go build -o tflint cmd/linter/main.go
./tflint -v examples/
```

### Pull Request Template

Use this template for your PR:

```markdown
## Description
Brief description of the changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests pass
- [ ] Manual testing completed
- [ ] Performance impact assessed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No breaking changes
- [ ] Tests added for new functionality
- [ ] All tests pass

## Related Issues
Closes #123
```

### Commit Message Format

Use conventional commit format:

```
type(scope): description

feat(rules): add new Azure security rule for VM encryption
fix(parser): handle malformed HCL gracefully
docs(readme): update installation instructions
test(aws): add comprehensive test coverage for S3 rules
```

## Code Review Guidelines 👀

### Review Checklist

When reviewing code, check for:

- [ ] **Functionality**: Does it work as intended?
- [ ] **Security**: Are there any security implications?
- [ ] **Performance**: Is it efficient and scalable?
- [ ] **Testability**: Is the code testable?
- [ ] **Documentation**: Is it well-documented?
- [ ] **Style**: Does it follow coding standards?
- [ ] **Edge Cases**: Are edge cases handled?

### Review Comments

Use constructive feedback:

```markdown
# Good
This is a good approach! Consider adding a test case for the edge case where the config is empty.

# Bad
This is wrong. Fix it.
```

### Approval Process

- **Two Approvals**: Required for all changes
- **Maintainer Review**: Required for security rules
- **CI/CD Checks**: All tests must pass
- **Documentation**: README updates reviewed

## Getting Help 💬

- **Issues**: [GitHub Issues](https://github.com/heyimusa/go-terraform-linter/issues)
- **Discussions**: [GitHub Discussions](https://github.com/heyimusa/go-terraform-linter/discussions)
- **Email**: [heyimusa@gmail.com]

## Recognition 🏆

Contributors will be recognized in:
- README.md contributors section
- Release notes
- GitHub contributors page

Thank you for contributing to Go Terraform Linter! 🎉 