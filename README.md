# Go Terraform Linter 🔍

A fast and comprehensive security-focused Terraform linter written in Go. This tool helps identify security misconfigurations, best practice violations, and potential vulnerabilities in your Terraform infrastructure code.

## Features ✨

- **Security-Focused Rules**: Detects common security misconfigurations
- **Fast Performance**: Written in Go for blazing-fast scanning
- **Colored Output**: Beautiful terminal output with severity indicators
- **JSON Reports**: Export detailed reports for CI/CD integration
- **Severity Filtering**: Filter issues by severity level
- **Multiple File Support**: Scans `.tf`, `.tfvars`, and `.tf.json` files

## Security Rules 🛡️

| Rule | Severity | Description |
|------|----------|-------------|
| `PUBLIC_ACCESS` | High | Detects public access configurations (S3 buckets, security groups) |
| `UNENCRYPTED_STORAGE` | High | Identifies unencrypted storage resources |
| `WEAK_PASSWORD` | Medium | Detects weak password configurations |
| `MISSING_TAGS` | Low | Resources without proper tagging |
| `EXPOSED_SECRETS` | Critical | Hardcoded secrets in configuration |
| `UNRESTRICTED_INGRESS` | High | Security groups with overly permissive rules |
| `DEPRECATED_RESOURCES` | Medium | Usage of deprecated Terraform resources |
| `MISSING_BACKUP` | High | Resources without backup configurations |
| `WEAK_CRYPTO` | Medium | Weak cryptographic configurations |
| `EXCESSIVE_PERMISSIONS` | High | IAM roles with excessive permissions |

## Installation 🚀

### From Source

```bash
# Clone the repository
git clone https://github.com/heyimusa/go-terraform-linter.git
cd go-terraform-linter

# Build the binary
go build -o tflint cmd/linter/main.go

# Make it executable
chmod +x tflint

# Move to your PATH (optional)
sudo mv tflint /usr/local/bin/
```

### Using Go Install

```bash
go install github.com/heyimusa/go-terraform-linter/cmd/linter@latest
```

## Usage 📖

### Basic Usage

```bash
# Scan current directory
./tflint

# Scan specific directory
./tflint -c /path/to/terraform/config

# Verbose output
./tflint -v

# Filter by severity
./tflint -s high

# Save detailed report
./tflint -o report.json
```

### Command Line Options

| Flag | Description | Default |
|------|-------------|---------|
| `-c, --config` | Path to Terraform configuration directory | `.` |
| `-o, --output` | Output file for detailed report (JSON) | - |
| `-s, --severity` | Minimum severity level (low, medium, high, critical, all) | `all` |
| `-v, --verbose` | Verbose output | `false` |

### Severity Levels

- **Critical**: Immediate security risks (hardcoded secrets)
- **High**: Significant security vulnerabilities (public access, unencrypted storage)
- **Medium**: Security concerns (weak passwords, deprecated resources)
- **Low**: Best practice violations (missing tags)

## Examples 📝

### Example Output

```
================================================================================
🔍 Terraform Security Scan Results
================================================================================

📊 Summary:
   Total Issues: 8
   Critical: 1
   High: 5
   Medium: 2

🔍 Detailed Issues:
--------------------------------------------------------------------------------

📁 File: examples/main.tf

  🚨 [CRITICAL] Hardcoded secret detected (line 7)
     Rule: EXPOSED_SECRETS
     Description: Secrets should be stored in variables or secret management systems

  ⚠️ [HIGH] S3 bucket has public read access (line 15)
     Rule: PUBLIC_ACCESS
     Description: Public read access allows anyone to read bucket contents

  ⚠️ [HIGH] EBS volume encryption not specified (line 21)
     Rule: UNENCRYPTED_STORAGE
     Description: EBS volumes should be encrypted by default

================================================================================
❌ Critical and High severity issues found!
```

### Example Terraform Configuration

```hcl
# This will trigger multiple security rules
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  acl    = "public-read"  # 🚨 PUBLIC_ACCESS rule
}

resource "aws_db_instance" "example" {
  identifier = "example-db"
  password   = "weak123"  # 🚨 EXPOSED_SECRETS and WEAK_PASSWORD rules
}
```

## Integration 🔧

### CI/CD Integration

```yaml
# GitHub Actions example
name: Terraform Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'
      
      - name: Run Terraform Linter
        run: |
          go run github.com/heyimusa/go-terraform-linter/cmd/linter@latest -o security-report.json
      
      - name: Upload Security Report
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: security-report.json
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: terraform-linter
        name: Terraform Security Linter
        entry: tflint
        language: system
        files: \.(tf|tfvars)$
```

## Contributing 🤝

Contributions are welcome! Please feel free to submit a Pull Request.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/heyimusa/go-terraform-linter.git
cd go-terraform-linter

# Install dependencies
go mod download

# Run tests
go test ./...

# Build
go build -o tflint cmd/linter/main.go

# Test with example files
./tflint -c examples/
```

### Adding New Rules

1. Create a new rule struct implementing the `Rule` interface
2. Add the rule to the `registerRules()` function in `internal/rules/rules.go`
3. Add tests for your rule
4. Update this README with the new rule

## License 📄

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments 🙏

- Inspired by security tools like [tfsec](https://github.com/aquasecurity/tfsec) and [checkov](https://github.com/bridgecrewio/checkov)
- Built with [HCL](https://github.com/hashicorp/hcl) for Terraform parsing
- Uses [Cobra](https://github.com/spf13/cobra) for CLI interface

## Roadmap 🗺️

- [ ] Support for Terraform modules
- [ ] Custom rule configuration
- [ ] Integration with more cloud providers (Azure, GCP)
- [ ] SARIF output format
- [ ] IDE integration (VS Code extension)
- [ ] Performance optimizations
- [ ] More security rules

---

**Made with ❤️ for the security community** 