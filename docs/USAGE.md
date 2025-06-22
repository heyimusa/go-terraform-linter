# 📖 Usage Guide

This guide covers how to use the Go Terraform Linter effectively in your projects.

## 📋 Table of Contents

- [Basic Usage](#basic-usage)
- [Command Line Options](#command-line-options)
- [Configuration Files](#configuration-files)
- [Output Formats](#output-formats)
- [Filtering and Exclusions](#filtering-and-exclusions)
- [CI/CD Integration](#cicd-integration)
- [Advanced Usage](#advanced-usage)
- [Examples](#examples)

## 🚀 Basic Usage

### Quick Start
```bash
# Scan current directory
terraform-linter .

# Scan specific directory
terraform-linter /path/to/terraform/files

# Scan specific file
terraform-linter main.tf
```

### Common Commands
```bash
# Show help
terraform-linter --help

# Show version
terraform-linter --version

# Verbose output
terraform-linter --verbose .

# Save output to file
terraform-linter --output report.txt .
```

## ⚙️ Command Line Options

### Basic Options
```bash
terraform-linter [OPTIONS] [PATH...]
```

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--help` | `-h` | Show help message | - |
| `--version` | `-v` | Show version information | - |
| `--verbose` | | Enable verbose output | false |
| `--quiet` | `-q` | Suppress output except errors | false |
| `--config` | `-c` | Configuration file path | `.terraform-linter.yml` |

### Output Options
| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--format` | `-f` | Output format (text, json, sarif, html) | text |
| `--output` | `-o` | Output file path | stdout |
| `--no-color` | | Disable colored output | false |
| `--template` | | Custom output template file | - |

### Filtering Options
| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--severity` | `-s` | Minimum severity level (low, medium, high, critical) | low |
| `--exclude` | `-e` | Exclude patterns (glob) | - |
| `--include` | `-i` | Include patterns (glob) | `**/*.tf,**/*.tfvars` |
| `--rules` | `-r` | Specific rules to run | all |
| `--ignore-rules` | | Rules to ignore | - |

### Performance Options
| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--parallel` | `-p` | Number of parallel workers | CPU count |
| `--cache` | | Enable caching | true |
| `--cache-dir` | | Cache directory | `.terraform-linter-cache` |
| `--timeout` | | Timeout per file (seconds) | 30 |

## 📝 Configuration Files

### Configuration File Locations
The linter looks for configuration files in this order:
1. File specified by `--config` flag
2. `.terraform-linter.yml` in current directory
3. `.terraform-linter.yaml` in current directory
4. `terraform-linter.yml` in current directory
5. `$HOME/.terraform-linter.yml`

### YAML Configuration
```yaml
# .terraform-linter.yml
version: "1.0"

# General settings
severity: "medium"
format: "text"
verbose: false
parallel: 4

# File patterns
include:
  - "**/*.tf"
  - "**/*.tfvars"
exclude:
  - "**/test/**"
  - "**/.terraform/**"
  - "**/examples/**"

# Rules configuration
rules:
  enabled:
    - "aws-s3-bucket-public-access-block"
    - "aws-ec2-security-group-ingress-ssh"
    - "gcp-compute-firewall-ingress-ssh"
  disabled:
    - "aws-s3-bucket-versioning"
  
  # Rule-specific settings
  settings:
    aws-s3-bucket-public-access-block:
      severity: "high"
      exceptions:
        - "public-website-bucket"
    
    aws-ec2-security-group-ingress-ssh:
      allowed_cidrs:
        - "10.0.0.0/8"
        - "192.168.0.0/16"

# Output settings
output:
  format: "json"
  file: "terraform-lint-report.json"
  template: "custom-template.tmpl"

# Cache settings
cache:
  enabled: true
  directory: ".terraform-linter-cache"
  ttl: "24h"

# Provider-specific settings
providers:
  aws:
    regions: ["us-east-1", "us-west-2"]
    profiles: ["default", "prod"]
  
  azure:
    subscription_ids: ["xxx-xxx-xxx"]
  
  gcp:
    project_ids: ["my-project-123"]

# Custom rules
custom_rules_dir: "./custom-rules"

# Notifications
notifications:
  slack:
    webhook_url: "${SLACK_WEBHOOK_URL}"
    channel: "#security"
  
  email:
    smtp_server: "smtp.company.com"
    recipients: ["security@company.com"]
```

### JSON Configuration
```json
{
  "version": "1.0",
  "severity": "medium",
  "format": "json",
  "include": ["**/*.tf", "**/*.tfvars"],
  "exclude": ["**/test/**", "**/.terraform/**"],
  "rules": {
    "enabled": [
      "aws-s3-bucket-public-access-block",
      "aws-ec2-security-group-ingress-ssh"
    ],
    "disabled": ["aws-s3-bucket-versioning"]
  },
  "output": {
    "format": "json",
    "file": "report.json"
  }
}
```

## 📊 Output Formats

### Text Format (Default)
```bash
terraform-linter --format text .
```
```
Issues found in main.tf:
  HIGH: AWS S3 bucket allows public access (line 5)
    The S3 bucket 'my-bucket' allows public read access
    
  MEDIUM: Security group allows SSH from anywhere (line 15)
    Security group 'web-sg' allows SSH (port 22) from 0.0.0.0/0

Summary: 2 issues found (1 high, 1 medium)
```

### JSON Format
```bash
terraform-linter --format json .
```
```json
{
  "issues": [
    {
      "rule": "aws-s3-bucket-public-access-block",
      "severity": "high",
      "message": "S3 bucket allows public access",
      "file": "main.tf",
      "line": 5,
      "column": 1,
      "resource": "aws_s3_bucket.my_bucket",
      "fix_suggestion": "Add public_access_block configuration"
    }
  ],
  "summary": {
    "total": 2,
    "by_severity": {
      "critical": 0,
      "high": 1,
      "medium": 1,
      "low": 0
    }
  }
}
```

### SARIF Format
```bash
terraform-linter --format sarif --output results.sarif .
```
SARIF format is compatible with GitHub Security tab and other security tools.

### HTML Format
```bash
terraform-linter --format html --output report.html .
```
Generates a beautiful HTML report with:
- Interactive dashboard
- Severity breakdown
- File-by-file analysis
- Fix suggestions
- Rule documentation links

## 🔍 Filtering and Exclusions

### Severity Filtering
```bash
# Only show high and critical issues
terraform-linter --severity high .

# Show all issues
terraform-linter --severity low .
```

### File Exclusions
```bash
# Exclude test files
terraform-linter --exclude "**/test/**" .

# Exclude multiple patterns
terraform-linter --exclude "**/test/**" --exclude "**/.terraform/**" .

# Include only specific files
terraform-linter --include "**/*.tf" .
```

### Rule Filtering
```bash
# Run only specific rules
terraform-linter --rules "aws-s3-*,aws-ec2-*" .

# Ignore specific rules
terraform-linter --ignore-rules "aws-s3-bucket-versioning" .
```

### Using Configuration File
```yaml
# .terraform-linter.yml
exclude:
  - "**/modules/third-party/**"
  - "**/test/**"
  - "**/.terraform/**"
  - "**/examples/**"

rules:
  disabled:
    - "aws-s3-bucket-versioning"  # Not required for dev environments
    - "gcp-compute-disk-encryption"  # Legacy systems exception
```

## 🔄 CI/CD Integration

### GitHub Actions
```yaml
# .github/workflows/terraform-lint.yml
name: Terraform Lint
on: [push, pull_request]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Go
        uses: actions/setup-go@v3
        with:
          go-version: '1.21'
      
      - name: Install Terraform Linter
        run: |
          curl -L https://github.com/heyimusa/go-terraform-linter/releases/latest/download/terraform-linter-linux-amd64 -o terraform-linter
          chmod +x terraform-linter
          sudo mv terraform-linter /usr/local/bin/
      
      - name: Run Terraform Linter
        run: |
          terraform-linter --format sarif --output results.sarif .
      
      - name: Upload SARIF results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

### GitLab CI
```yaml
# .gitlab-ci.yml
terraform-lint:
  stage: test
  image: golang:1.21
  script:
    - curl -L https://github.com/heyimusa/go-terraform-linter/releases/latest/download/terraform-linter-linux-amd64 -o terraform-linter
    - chmod +x terraform-linter
    - ./terraform-linter --format json --output terraform-lint-report.json .
  artifacts:
    reports:
      junit: terraform-lint-report.json
    paths:
      - terraform-lint-report.json
  only:
    - merge_requests
    - main
```

### Jenkins Pipeline
```groovy
pipeline {
    agent any
    
    stages {
        stage('Terraform Lint') {
            steps {
                sh '''
                    curl -L https://github.com/heyimusa/go-terraform-linter/releases/latest/download/terraform-linter-linux-amd64 -o terraform-linter
                    chmod +x terraform-linter
                    ./terraform-linter --format json --output terraform-lint-report.json .
                '''
                
                publishHTML([
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: '.',
                    reportFiles: 'terraform-lint-report.json',
                    reportName: 'Terraform Lint Report'
                ])
            }
        }
    }
}
```

### Pre-commit Hook
```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: terraform-lint
        name: Terraform Lint
        entry: terraform-linter
        language: system
        files: \.tf$
        args: ['--severity', 'medium']
```

## 🔧 Advanced Usage

### Custom Templates
Create a custom output template:

```go
// custom-template.tmpl
{{range .Issues}}
🚨 {{.Severity | upper}}: {{.Message}}
   📁 File: {{.File}}:{{.Line}}
   🔧 Fix: {{.FixSuggestion}}
   
{{end}}

📊 Summary: {{.Summary.Total}} issues found
   🔴 Critical: {{.Summary.BySeverity.Critical}}
   🟠 High: {{.Summary.BySeverity.High}}
   🟡 Medium: {{.Summary.BySeverity.Medium}}
   🟢 Low: {{.Summary.BySeverity.Low}}
```

```bash
terraform-linter --template custom-template.tmpl .
```

### Environment Variables
```bash
# Configuration via environment variables
export TF_LINTER_CONFIG="/path/to/config.yml"
export TF_LINTER_SEVERITY="high"
export TF_LINTER_FORMAT="json"
export TF_LINTER_PARALLEL="8"

terraform-linter .
```

### Programmatic Usage
```go
package main

import (
    "github.com/heyimusa/go-terraform-linter/internal/linter"
    "github.com/heyimusa/go-terraform-linter/internal/config"
)

func main() {
    cfg := &config.Config{
        Severity: "medium",
        Format:   "json",
        Paths:    []string{"."},
    }
    
    l := linter.New(cfg)
    results, err := l.Run()
    if err != nil {
        panic(err)
    }
    
    // Process results...
}
```

## 📚 Examples

### Example 1: Basic Security Scan
```bash
# Scan for security issues only
terraform-linter --severity medium --rules "security-*" .
```

### Example 2: Generate HTML Report
```bash
# Create comprehensive HTML report
terraform-linter \
  --format html \
  --output security-report.html \
  --severity low \
  --verbose \
  ./infrastructure
```

### Example 3: CI Pipeline with Specific Rules
```bash
# CI-friendly output with specific AWS rules
terraform-linter \
  --format json \
  --output results.json \
  --rules "aws-s3-*,aws-ec2-*,aws-iam-*" \
  --severity high \
  --exclude "**/test/**" \
  .
```

### Example 4: Development Environment
```bash
# Quick scan for development
terraform-linter \
  --severity medium \
  --no-color \
  --exclude "**/dev/**" \
  --parallel 2 \
  .
```

### Example 5: Production Deployment Check
```bash
# Strict production checks
terraform-linter \
  --config .terraform-linter-prod.yml \
  --severity critical \
  --format sarif \
  --output prod-security-scan.sarif \
  ./production
```

### Example 6: Multi-Cloud Scan
```bash
# Scan multiple cloud providers
terraform-linter \
  --rules "aws-*,azure-*,gcp-*" \
  --format html \
  --output multi-cloud-report.html \
  ./cloud-infrastructure
```

## 🐛 Troubleshooting

### Common Issues

#### Large Repository Performance
```bash
# Optimize for large repositories
terraform-linter \
  --parallel 8 \
  --cache \
  --timeout 60 \
  --exclude "**/.terraform/**" \
  .
```

#### Memory Usage
```bash
# Reduce memory usage
terraform-linter \
  --parallel 2 \
  --include "*.tf" \
  --exclude "**/modules/**" \
  .
```

#### False Positives
```yaml
# .terraform-linter.yml - Configure rule exceptions
rules:
  settings:
    aws-s3-bucket-public-access-block:
      exceptions:
        - "public-website-*"
        - "*-cdn-bucket"
```

### Getting Help

- Check the [Troubleshooting Guide](TROUBLESHOOTING.md)
- Review [Configuration Examples](CONFIGURATION.md)
- See [Rule Documentation](RULES.md)
- Visit [GitHub Issues](https://github.com/heyimusa/go-terraform-linter/issues)

---

**Next Steps**: 
- Learn about [Configuration Options](CONFIGURATION.md)
- Explore [Available Rules](RULES.md)
- Check [Development Guide](DEVELOPMENT.md) for contributing 