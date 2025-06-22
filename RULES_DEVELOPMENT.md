# Rule Development Guide

This guide covers how to develop, test, and distribute custom rules for the Go Terraform Linter using the new Rule SDK and Marketplace system.

## Table of Contents

- [Overview](#overview)
- [Rule SDK](#rule-sdk)
- [Rule Marketplace](#rule-marketplace)
- [Built-in Rules](#built-in-rules)
- [Custom Rule Development](#custom-rule-development)
- [Dynamic Rule Loading](#dynamic-rule-loading)
- [Testing Rules](#testing-rules)
- [Publishing Rules](#publishing-rules)
- [Examples](#examples)

## Overview

The Go Terraform Linter now supports:

- **Expanded Rule Library**: 60+ built-in rules covering AWS, Azure, GCP, and Kubernetes
- **Custom Rule SDK**: Fluent API for easy rule development
- **Rule Marketplace**: Discover, install, and manage rule packages
- **Dynamic Rule Loading**: Load rules from JSON/YAML files at runtime

## Rule SDK

### Quick Start

```go
package main

import (
    "github.com/heyimusa/go-terraform-linter/internal/rules"
)

func main() {
    // Create a simple rule using the SDK
    rule, err := rules.NewRuleBuilder("MY_CUSTOM_RULE").
        WithDescription("Detects my custom security issue").
        WithSeverity("high").
        WithCategory("security").
        WithProvider("aws").
        WithTags("security", "custom").
        ForResource("aws_s3_bucket").
        WithAttributeEquals("acl", "public-read").
        WithCustomMessage("S3 bucket should not be publicly readable").
        WithCompliance("SOC2", "PCI-DSS").
        WithCWE("CWE-200").
        WithRiskScore(8).
        Build()
    
    if err != nil {
        panic(err)
    }
    
    // Add to engine
    engine := rules.NewRuleEngine()
    engine.AddCustomRule(rule)
}
```

### Rule Builder Methods

#### Basic Configuration
- `WithDescription(description)` - Set rule description
- `WithSeverity(severity)` - Set severity (low, medium, high, critical)
- `WithCategory(category)` - Set category (security, network, storage, etc.)
- `WithProvider(provider)` - Set cloud provider (aws, azure, gcp, kubernetes)
- `WithTags(tags...)` - Add tags for categorization
- `WithVersion(version)` - Set rule version

#### Compliance and Risk
- `WithCompliance(standards...)` - Add compliance standards (SOC2, PCI-DSS, HIPAA, etc.)
- `WithCWE(cweIds...)` - Add Common Weakness Enumeration IDs
- `WithRiskScore(score)` - Set risk score (1-10)
- `WithDocsURL(url)` - Set documentation URL

#### Conditions
- `ForResource(resourceType)` - Target specific resource type
- `WithAttributeEquals(attr, value)` - Check attribute equals value
- `WithAttributeContains(attr, value)` - Check attribute contains value
- `WithAttributeRegex(attr, pattern)` - Check attribute matches regex
- `WithAttributeExists(attr)` - Check attribute exists
- `WithAttributeNotExists(attr)` - Check attribute doesn't exist

#### Advanced Features
- `WithValidator(func)` - Add custom validation logic
- `WithProcessor(func)` - Add custom processing logic
- `WithCustomMessage(message)` - Set custom message for last condition

### Common Patterns

The SDK provides pre-built patterns for common security issues:

```go
patterns := rules.NewCommonPatterns()

// Public access rule
rule1, _ := patterns.PublicAccessRule("aws", "aws_s3_bucket").
    WithAttributeEquals("acl", "public-read").
    Build()

// Unencrypted storage rule
rule2, _ := patterns.UnencryptedStorageRule("aws", "aws_ebs_volume").
    WithAttributeEquals("encrypted", false).
    Build()

// Weak password rule
rule3, _ := patterns.WeakPasswordRule("aws", "aws_db_instance").
    WithValidator(func(block *types.Block, condition RuleCondition) bool {
        // Custom password strength validation
        return true
    }).
    Build()
```

### Rule Helpers

```go
helpers := rules.NewRuleHelpers()

// Check if CIDR is public
isPublic := helpers.IsPublicCIDR("0.0.0.0/0") // true

// Check if port is dangerous
isDangerous := helpers.IsDangerousPort("22") // true

// Check for weak encryption
isWeak := helpers.HasWeakEncryption("none") // true

// Extract string values safely
value := helpers.ExtractStringValue(attributeValue)
```

## Rule Marketplace

### Configuration

Create a marketplace configuration file:

```yaml
# ~/.go-terraform-linter/marketplace.yaml
repositories:
  - name: official
    url: https://rules.go-terraform-linter.com
    type: http
    enabled: true
  
  - name: community
    url: https://github.com/go-terraform-linter/community-rules
    type: git
    branch: main
    enabled: true
  
  - name: local
    path: /usr/local/share/go-terraform-linter/rules
    type: local
    enabled: true

cache_dir: ~/.go-terraform-linter/cache
timeout: 30s
auto_update: true
```

### CLI Commands

```bash
# Search for rules
go-terraform-linter rules search aws

# Install a rule package
go-terraform-linter rules install aws-security-pack

# List installed packages
go-terraform-linter rules list

# Update a package
go-terraform-linter rules update aws-security-pack

# Uninstall a package
go-terraform-linter rules uninstall aws-security-pack

# Show package info
go-terraform-linter rules info aws-security-pack
```

### Programmatic Usage

```go
// Create marketplace
config := rules.MarketplaceConfig{
    Repositories: []rules.Repository{
        {
            Name: "official",
            URL:  "https://rules.go-terraform-linter.com",
            Type: "http",
            Enabled: true,
        },
    },
}

registry := rules.NewRuleRegistry()
marketplace := rules.NewRuleMarketplace(config, registry)

// Search for rules
packages, err := marketplace.SearchRules("aws security")

// Install a package
err = marketplace.InstallPackage("aws-security-pack", "latest")

// List installed packages
installed := marketplace.ListInstalledPackages()
```

## Built-in Rules

### AWS Rules (25+)
- `AWS_PUBLIC_S3_BUCKET` - Public S3 buckets
- `AWS_UNENCRYPTED_STORAGE` - Unencrypted EBS/RDS
- `AWS_OPEN_PORTS` - Open security group ports
- `AWS_EXPOSED_SECRETS` - Hardcoded secrets
- `AWS_EXCESSIVE_PERMISSIONS` - Overprivileged IAM roles
- And many more...

### Azure Rules (20+)
- `AZURE_PUBLIC_ACCESS` - Public access configurations
- `AZURE_UNENCRYPTED_STORAGE` - Unencrypted storage accounts
- `AZURE_WEAK_PASSWORD` - Weak password configurations
- `AZURE_OPEN_PORTS` - Open network security groups
- And many more...

### GCP Rules (15+)
- `GCP_PUBLIC_STORAGE` - Public GCS buckets
- `GCP_OPEN_FIREWALL` - Open firewall rules
- `GCP_IAM_OVERPRIVILEGED` - Overprivileged IAM roles
- `GCP_PUBLIC_COMPUTE_INSTANCE` - Public compute instances
- And many more...

### Kubernetes Rules (10+)
- `K8S_PRIVILEGED_CONTAINER` - Privileged containers
- `K8S_ROOT_USER` - Containers running as root
- `K8S_DANGEROUS_CAPABILITIES` - Dangerous Linux capabilities
- `K8S_HOST_NETWORK` - Host network usage
- And many more...

## Custom Rule Development

### JSON/YAML Rule Definition

Create a rule definition file:

```json
{
  "id": "my-custom-rule",
  "name": "MY_CUSTOM_RULE",
  "description": "My custom security rule",
  "severity": "high",
  "category": "security",
  "provider": "aws",
  "tags": ["security", "custom"],
  "version": "1.0.0",
  "enabled": true,
  "risk_score": 7,
  "compliance": ["SOC2"],
  "cwe": ["CWE-200"],
  "conditions": [
    {
      "type": "resource",
      "resource_type": "aws_s3_bucket",
      "operator": "exists"
    },
    {
      "type": "attribute",
      "resource_type": "aws_s3_bucket",
      "attribute": "versioning",
      "operator": "not_exists",
      "message": "S3 bucket should have versioning enabled"
    }
  ]
}
```

### Loading Custom Rules

```bash
# Load from file
go-terraform-linter --custom-rules ./my-rule.json scan ./terraform

# Load from directory
go-terraform-linter --custom-rules-dir ./custom-rules scan ./terraform
```

### Programmatic Loading

```go
engine := rules.NewRuleEngine()

// Load from file
err := engine.LoadRuleFromFile("./my-rule.json")

// Load from directory
err = engine.LoadRulesFromDirectory("./custom-rules")
```

## Dynamic Rule Loading

### Rule Conditions

#### Resource Conditions
```json
{
  "type": "resource",
  "resource_type": "aws_s3_bucket",
  "operator": "exists"
}
```

#### Attribute Conditions
```json
{
  "type": "attribute",
  "resource_type": "aws_s3_bucket",
  "attribute": "acl",
  "operator": "equals",
  "value": "public-read",
  "message": "Custom message for this condition"
}
```

#### Supported Operators
- `exists` - Attribute or resource exists
- `not_exists` - Attribute or resource doesn't exist
- `equals` - Attribute equals value
- `contains` - Attribute contains value
- `regex` - Attribute matches regex pattern
- `greater_than` - Attribute value is greater than
- `less_than` - Attribute value is less than

## Testing Rules

### Unit Testing

```go
func TestMyCustomRule(t *testing.T) {
    rule, err := rules.NewRuleBuilder("TEST_RULE").
        WithDescription("Test rule").
        WithSeverity("high").
        WithCategory("security").
        WithProvider("aws").
        ForResource("aws_s3_bucket").
        WithAttributeEquals("acl", "public-read").
        Build()
    
    require.NoError(t, err)
    
    // Create test configuration
    config := &parser.Config{
        Blocks: []*types.Block{
            {
                Type:   "resource",
                Labels: []string{"aws_s3_bucket", "test"},
                Attributes: map[string]*types.Attribute{
                    "acl": {
                        Value: "public-read",
                        Range: hcl.Range{Start: hcl.Pos{Line: 1}},
                    },
                },
            },
        },
    }
    
    issues := rule.Check(config)
    assert.Len(t, issues, 1)
    assert.Equal(t, "TEST_RULE", issues[0].Rule)
}
```

### Integration Testing

```bash
# Test with sample Terraform files
go-terraform-linter --custom-rules ./my-rule.json scan ./test-fixtures
```

## Publishing Rules

### Rule Package Structure

```
my-rule-package/
├── package.json          # Package metadata
├── rules/
│   ├── rule1.json        # Rule definitions
│   ├── rule2.yaml
│   └── rule3.json
├── tests/
│   ├── fixtures/         # Test Terraform files
│   └── expected/         # Expected results
├── README.md
└── CHANGELOG.md
```

### Package Definition

```json
{
  "name": "my-security-pack",
  "version": "1.0.0",
  "description": "My custom security rules",
  "author": "Your Name",
  "license": "MIT",
  "homepage": "https://github.com/yourname/my-security-pack",
  "keywords": ["security", "terraform", "custom"],
  "provider": "multi",
  "category": "security",
  "rules": [
    // Rule definitions or references to rule files
  ]
}
```

### Publishing to Marketplace

1. Create a GitHub repository with your rule package
2. Tag releases with semantic versioning
3. Submit to the community marketplace
4. Or host your own marketplace endpoint

## Examples

### Complete Example: AWS Lambda Security Rule

```go
// Create a rule to detect Lambda functions without dead letter queues
rule, err := rules.NewRuleBuilder("AWS_LAMBDA_NO_DLQ").
    WithDescription("Detects Lambda functions without dead letter queue configuration").
    WithSeverity("medium").
    WithCategory("reliability").
    WithProvider("aws").
    WithTags("aws", "lambda", "reliability", "error-handling").
    WithCompliance("AWS-WA").
    WithCWE("CWE-754").
    WithRiskScore(5).
    WithDocsURL("https://docs.aws.amazon.com/lambda/latest/dg/invocation-async.html#dlq").
    ForResource("aws_lambda_function").
    WithAttributeNotExists("dead_letter_config").
    WithCustomMessage("Lambda function should have dead letter queue configured for error handling").
    WithProcessor(func(block *types.Block, condition RuleCondition) *types.Issue {
        // Custom logic to check if DLQ is properly configured
        if dlqConfig, exists := block.Attributes["dead_letter_config"]; exists {
            // Check if DLQ target ARN is specified
            for _, nestedBlock := range block.Blocks {
                if nestedBlock.Type == "dead_letter_config" {
                    if _, hasTarget := nestedBlock.Attributes["target_arn"]; !hasTarget {
                        return &types.Issue{
                            Rule:        "AWS_LAMBDA_NO_DLQ",
                            Message:     "Dead letter config exists but target ARN is not specified",
                            Description: "Lambda dead letter queue must have a target ARN",
                            Severity:    "medium",
                            Line:        dlqConfig.Range.Start.Line,
                        }
                    }
                }
            }
        }
        return nil
    }).
    Build()
```

### JSON Rule Example: GCP Storage Bucket Versioning

```json
{
  "id": "gcp-storage-versioning",
  "name": "GCP_STORAGE_VERSIONING",
  "description": "Detects GCP storage buckets without versioning enabled",
  "severity": "medium",
  "category": "data-protection",
  "provider": "gcp",
  "tags": ["gcp", "storage", "versioning", "data-protection"],
  "version": "1.0.0",
  "enabled": true,
  "risk_score": 6,
  "compliance": ["SOC2"],
  "cwe": ["CWE-404"],
  "docs_url": "https://cloud.google.com/storage/docs/object-versioning",
  "conditions": [
    {
      "type": "resource",
      "resource_type": "google_storage_bucket",
      "operator": "exists"
    },
    {
      "type": "attribute",
      "resource_type": "google_storage_bucket",
      "attribute": "versioning",
      "operator": "not_exists",
      "message": "GCP storage bucket should have versioning enabled for data protection"
    }
  ],
  "metadata": {
    "author": "Security Team",
    "created": "2024-01-01",
    "impact": "Medium - Data loss risk without versioning",
    "remediation": "Add versioning block with enabled = true"
  }
}
```

## Best Practices

1. **Rule Naming**: Use descriptive, consistent naming (PROVIDER_RESOURCE_ISSUE)
2. **Severity Levels**: Use appropriate severity levels based on security impact
3. **Clear Messages**: Provide clear, actionable messages
4. **Documentation**: Include links to relevant documentation
5. **Testing**: Test rules with various Terraform configurations
6. **Compliance**: Map rules to relevant compliance standards
7. **Versioning**: Use semantic versioning for rule packages
8. **Performance**: Avoid overly complex conditions that slow down scanning

## Contributing

1. Fork the repository
2. Create feature branch
3. Add your rules with tests
4. Update documentation
5. Submit pull request

For more information, see the [Contributing Guide](CONTRIBUTING.md). 