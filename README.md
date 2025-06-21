# Go Terraform Linter 🔍

A fast and comprehensive security-focused Terraform linter written in Go. This tool helps identify security misconfigurations, best practice violations, and potential vulnerabilities in your Terraform infrastructure code.

## Features ✨

- **Comprehensive Security Rules**: 14+ security rules covering network, IAM, compliance, and cost optimization
- **Multiple Output Formats**: Text, JSON, SARIF, and HTML reports for CI/CD integration
- **Parallel Processing**: Fast scanning with concurrent file analysis
- **Fix Suggestions**: Actionable recommendations for each issue
- **Configuration Support**: Custom rules, severity overrides, and exclude patterns via YAML/JSON
- **Plugin System**: Extensible architecture for custom rules (coming soon)
- **Graceful Error Handling**: Continues scanning even when some files fail
- **Colored Output**: Beautiful terminal output with severity indicators
- **Severity Filtering**: Filter issues by severity level
- **Multiple File Support**: Scans `.tf`, `.tfvars`, and `.tf.json` files

## Architecture 🏗️

The linter follows a modular architecture designed for maintainability, extensibility, and clear separation of concerns:

### Directory Structure

```
go-terraform-linter/
├── cmd/
│   └── linter/
│       └── main.go              # CLI entry point
├── internal/
│   ├── cache/                   # Caching layer (future)
│   ├── linter/
│   │   └── linter.go           # Core linting engine
│   ├── parser/
│   │   └── parser.go           # Terraform HCL parser
│   ├── report/
│   │   ├── formats/            # Output format handlers
│   │   └── report.go           # Report generation
│   ├── rules/
│   │   ├── custom/
│   │   │   └── yaml.go         # Custom rule support
│   │   ├── security/           # Security rule modules
│   │   │   ├── auth.go         # Authentication & IAM rules
│   │   │   ├── best_practices.go # General security practices
│   │   │   ├── cost.go         # Cost optimization rules
│   │   │   ├── network.go      # Network security rules
│   │   │   └── storage.go      # Storage & encryption rules
│   │   ├── engine.go           # Rule execution engine
│   │   └── interface.go        # Rule interface definitions
│   └── types/
│       └── types.go            # Shared data structures
├── examples/
│   └── main.tf                 # Example Terraform files
└── docs/                       # Documentation
```

### Core Components

#### 1. **Parser** (`internal/parser/`)
- **Purpose**: Parse Terraform HCL files into structured data
- **Key Features**: 
  - HCL syntax parsing with `hclsyntax` package
  - Block and attribute extraction
  - Error handling for malformed files
  - Support for `.tf`, `.tfvars`, and `.tf.json` files

#### 2. **Rules Engine** (`internal/rules/`)
- **Purpose**: Execute security rules against parsed Terraform configurations
- **Architecture**:
  - **Interface-based**: All rules implement the `Rule` interface
  - **Modular**: Rules organized by security domain
  - **Extensible**: Easy to add new rules without modifying existing code
  - **Parallel**: Rules can be executed concurrently for performance

#### 3. **Security Rules** (`internal/rules/security/`)
Organized into specialized modules:

- **`auth.go`**: Authentication and IAM security
  - IAM least privilege violations
  - Excessive permissions detection
  - Weak authentication configurations

- **`network.go`**: Network security and access control
  - Public access detection
  - Open port analysis
  - Security group misconfigurations

- **`storage.go`**: Storage and encryption security
  - Unencrypted storage detection
  - Backup configuration validation
  - Encryption compliance checks

- **`best_practices.go`**: General security best practices
  - Resource tagging requirements
  - Deprecated resource detection
  - Configuration best practices

- **`cost.go`**: Cost optimization and resource efficiency
  - Expensive instance type detection
  - Resource sizing recommendations
  - Cost optimization suggestions

#### 4. **Custom Rules** (`internal/rules/custom/`)
- **Purpose**: Support for user-defined rules
- **Features**:
  - YAML/JSON-based rule definitions
  - Dynamic rule loading
  - Custom severity levels
  - Extensible rule engine

#### 5. **Report Generation** (`internal/report/`)
- **Purpose**: Generate formatted security reports
- **Supported Formats**:
  - **Text**: Human-readable console output
  - **JSON**: Machine-readable structured data
  - **SARIF**: Static Analysis Results Interchange Format
  - **HTML**: Web-friendly detailed reports

#### 6. **Types** (`internal/types/`)
- **Purpose**: Shared data structures across packages
- **Key Types**:
  - `Issue`: Standardized issue representation
  - `Block`: Parsed Terraform block structure
  - `Attribute`: Parsed attribute information

### Design Principles

#### 1. **Separation of Concerns**
- Each package has a single, well-defined responsibility
- Clear boundaries between parsing, analysis, and reporting
- Minimal coupling between components

#### 2. **Interface-based Design**
- Rules implement a common interface for consistency
- Easy to add new rule types without modifying existing code
- Testable components with clear contracts

#### 3. **Modularity**
- Security rules split by domain for better organization
- Independent modules that can be developed and tested separately
- Clear import structure to avoid circular dependencies

#### 4. **Extensibility**
- Plugin architecture for custom rules
- Configuration-driven behavior
- Multiple output format support

#### 5. **Performance**
- Parallel processing where possible
- Efficient parsing with minimal memory usage
- Caching-ready architecture for future optimizations

### Adding New Rules

To add a new security rule:

1. **Choose the appropriate module** in `internal/rules/security/`
2. **Implement the Rule interface**:
   ```go
   type Rule interface {
       Name() string
       Description() string
       Severity() string
       Check(block *types.Block) []*types.Issue
   }
   ```
3. **Register the rule** in the appropriate module's `init()` function
4. **Add tests** for the new rule
5. **Update documentation** with rule details

### Benefits of Modular Architecture

- **Maintainability**: Easy to locate and modify specific functionality
- **Testability**: Each module can be tested independently
- **Scalability**: New rules and features can be added without affecting existing code
- **Team Development**: Multiple developers can work on different modules simultaneously
- **Code Reuse**: Common functionality shared across modules
- **Performance**: Optimized imports and reduced memory footprint

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
| `OPEN_PORTS` | High | Sensitive ports (22, 3389, 80, 443) open to the world |
| `IAM_LEAST_PRIVILEGE` | High | IAM policies allowing all actions (*) |
| `ENCRYPTION_COMPLIANCE` | Critical | Missing encryption for compliance (HIPAA, SOC2, PCI-DSS) |
| `COST_OPTIMIZATION` | Medium | Large/expensive instance types detected |

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

# Multiple output formats
./tflint -f json
./tflint -f sarif
./tflint -f html

# Save detailed report
./tflint -o report.json -f json
./tflint -o report.sarif -f sarif
./tflint -o report.html -f html
```

### Advanced Usage

```bash
# Exclude specific files/patterns
./tflint --exclude "*.tfvars,test/"

# Use configuration file
./tflint --config-file .tflint.yaml

# Combine multiple options
./tflint -c ./terraform -s high -f json -o report.json --exclude "*.tfvars"
```

### Command Line Options

| Flag | Description | Default |
|------|-------------|---------|
| `-c, --config` | Path to Terraform configuration directory | `.` |
| `-o, --output` | Output file for detailed report | - |
| `-s, --severity` | Minimum severity level (low, medium, high, critical, all) | `all` |
| `-v, --verbose` | Verbose output | `false` |
| `-f, --format` | Output format (text, json, sarif, html) | `text` |
| `--exclude` | Exclude files matching patterns (comma-separated) | - |
| `--config-file` | Path to YAML/JSON config file | - |

### Severity Levels

- **Critical**: Immediate security risks (hardcoded secrets, missing encryption)
- **High**: Significant security vulnerabilities (public access, unencrypted storage, open ports)
- **Medium**: Security concerns (weak passwords, deprecated resources, cost optimization)
- **Low**: Best practice violations (missing tags)

## Configuration 📋

### Configuration File (.tflint.yaml)

```yaml
# Exclude patterns
exclude:
  - "*.tfvars"
  - "test/"
  - "examples/"

# Severity overrides
severity:
  MISSING_TAGS: medium
  COST_OPTIMIZATION: low

# Custom rules (coming soon)
custom_rules:
  - name: "CUSTOM_RULE"
    description: "Custom security rule"
    severity: "high"
```

## Examples 📝

### Example Output (Text Format)

```
================================================================================
🔍 Terraform Security Scan Results
================================================================================

📊 Summary:
   Total Issues: 12
   Critical: 2
   High: 6
   Medium: 3
   Low: 1

🔍 Detailed Issues:
--------------------------------------------------------------------------------

📁 File: examples/main.tf

  🚨 [CRITICAL] Hardcoded secret detected (line 7)
     Rule: EXPOSED_SECRETS
     Description: Secrets should be stored in variables or secret management systems
     Fix: Store secrets in variables or secret management systems

  ⚠️ [HIGH] Sensitive port open to the world (line 25)
     Rule: OPEN_PORTS
     Description: Port opened to 0.0.0.0/0 (world). Restrict access to trusted IPs.
     Fix: Restrict 'cidr_blocks' to trusted IP ranges

  ⚠️ [HIGH] IAM policy allows all actions (*) (line 65)
     Rule: IAM_LEAST_PRIVILEGE
     Description: Use least privilege principle. Avoid wildcard actions.
     Fix: Avoid using 'Action: *' and 'Resource: *' in IAM policies

================================================================================
❌ Critical and High severity issues found!
```

### Example Output (JSON Format)

```json
{
  "issues": [
    {
      "file": "examples/main.tf",
      "rule": "EXPOSED_SECRETS",
      "message": "Hardcoded secret detected",
      "description": "Secrets should be stored in variables or secret management systems",
      "severity": "critical",
      "line": 7,
      "fix_suggestion": "Store secrets in variables or secret management systems"
    }
  ],
  "stats": {
    "total": 12,
    "critical": 2,
    "high": 6,
    "medium": 3,
    "low": 1,
    "files": 1
  }
}
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

resource "aws_security_group" "open" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # 🚨 OPEN_PORTS rule
  }
}

resource "aws_iam_role" "admin" {
  inline_policy {
    policy = jsonencode({
      Statement = [{
        Effect = "Allow"
        Action = "*"  # 🚨 IAM_LEAST_PRIVILEGE rule
        Resource = "*"
      }]
    })
  }
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
          go run github.com/heyimusa/go-terraform-linter/cmd/linter@latest \
            -f json -o security-report.json \
            --exclude "*.tfvars,test/"
      
      - name: Upload Security Report
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: security-report.json
      
      - name: SARIF Upload
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: security-report.sarif
```

### SonarQube Integration

```bash
# Generate SARIF report for SonarQube
./tflint -f sarif -o sonar-report.sarif
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
        args: ["-s", "medium", "-f", "json"]
```

## Performance 🚀

- **Parallel Processing**: Files are analyzed concurrently for faster results
- **Efficient Parsing**: Optimized HCL parser for Terraform syntax
- **Memory Efficient**: Streams results without loading entire codebase into memory
- **Caching Ready**: Architecture supports future caching implementation

## Contributing 🤝

Contributions are welcome! Please feel free to submit a Pull Request.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/heyimusa/go-terraform-linter.git
cd go-terraform-linter

# Install dependencies
go mod download

# Build and test
go build -o tflint cmd/linter/main.go
./tflint -c examples/ -v
```

### Adding New Rules

1. Create a new rule struct implementing the `Rule` interface
2. Add the rule to the `registerRules()` function
3. Add fix suggestions in the `addFixSuggestion()` function
4. Update tests and documentation

## Roadmap 🗺️

- [ ] **Plugin System**: Support for user-defined Go plugins
- [ ] **Caching**: Cache results for unchanged files
- [ ] **Incremental Scanning**: Only scan changed files
- [ ] **Custom Rule Engine**: YAML/JSON-based custom rules
- [ ] **IDE Integration**: VS Code, IntelliJ plugins
- [ ] **Cloud Provider Rules**: Azure, GCP, and other providers
- [ ] **Compliance Frameworks**: HIPAA, SOC2, PCI-DSS specific rules

## License 📄

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support 💬

- **Issues**: [GitHub Issues](https://github.com/heyimusa/go-terraform-linter/issues)
- **Discussions**: [GitHub Discussions](https://github.com/heyimusa/go-terraform-linter/discussions)
- **Documentation**: [Wiki](https://github.com/heyimusa/go-terraform-linter/wiki) 