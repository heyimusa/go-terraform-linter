# Go Terraform Linter 🔍

A fast and comprehensive **multi-cloud security-focused** Terraform linter written in Go. This tool helps identify security misconfigurations, best practice violations, and potential vulnerabilities in your Terraform infrastructure code across **Azure, AWS, and general cloud resources**.

## Features ✨

- **🌐 Multi-Cloud Security**: Comprehensive rules for Azure, AWS, and general cloud resources
- **🔒 Advanced Secret Detection**: Detects hardcoded credentials, API keys, database connection strings, and OAuth secrets
- **⚡ Fast Parallel Processing**: Concurrent file analysis for maximum performance
- **📊 Multiple Output Formats**: Text, JSON, SARIF, and HTML reports for CI/CD integration
- **🎯 40+ Security Rules**: Covering network security, IAM, compliance, cost optimization, and more
- **🔧 Highly Configurable**: Custom rules, severity overrides, and exclude patterns via YAML/JSON
- **🎨 Beautiful Output**: Colored terminal output with severity indicators and detailed descriptions
- **🚀 Production Ready**: Successfully detects real-world security vulnerabilities
- **📝 Actionable Reports**: Fix suggestions and detailed descriptions for each issue
- **🔄 CI/CD Ready**: SARIF output format for GitHub Security tab integration

## Supported Cloud Providers 🌩️

### Azure (14 Rules)
- Hardcoded Azure provider credentials
- Public access configurations
- Unencrypted storage resources
- Weak authentication settings
- Missing resource tags
- Network security misconfigurations

### AWS (13 Rules) 
- Hardcoded AWS Access Keys and Secret Keys
- Public S3 bucket configurations
- Unencrypted storage (EBS, RDS, S3)
- IAM excessive permissions
- Security group misconfigurations
- Missing backup configurations

### General Cloud (15+ Rules)
- Authentication and authorization
- Network security
- Storage encryption
- Best practices compliance

## Security Rules Overview 🛡️

### Critical Severity Rules
| Rule | Azure | AWS | Description |
|------|-------|-----|-------------|
| `EXPOSED_SECRETS` | ✅ | ✅ | Detects hardcoded credentials, API keys, OAuth secrets |
| `PUBLIC_ACCESS` | ✅ | ✅ | Identifies publicly accessible resources |
| `UNRESTRICTED_INGRESS` | ✅ | ✅ | Security groups allowing 0.0.0.0/0 access |
| `ENCRYPTION_COMPLIANCE` | ✅ | ✅ | Missing encryption for compliance standards |

### High Severity Rules
| Rule | Azure | AWS | Description |
|------|-------|-----|-------------|
| `UNENCRYPTED_STORAGE` | ✅ | ✅ | Storage resources without encryption |
| `WEAK_PASSWORDS` | ✅ | ✅ | Weak or predictable password configurations |
| `EXCESSIVE_PERMISSIONS` | ✅ | ✅ | IAM policies with wildcard permissions |
| `WEAK_CRYPTO` | ✅ | ✅ | Weak SSL/TLS configurations |

### Medium Severity Rules
| Rule | Azure | AWS | Description |
|------|-------|-----|-------------|
| `MISSING_BACKUP` | ✅ | ✅ | Critical resources without backup |
| `DEPRECATED_RESOURCES` | ✅ | ✅ | Usage of deprecated resource types |
| `OPEN_PORTS` | ✅ | ✅ | Dangerous ports open to public |

### Low Severity Rules
| Rule | Azure | AWS | Description |
|------|-------|-----|-------------|
| `MISSING_TAGS` | ✅ | ✅ | Resources without proper tagging |
| `COST_OPTIMIZATION` | ✅ | ✅ | Expensive resource configurations |

## Installation 🚀

### From Source (Recommended)

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
./tflint /path/to/terraform/config

# Verbose output with debug information
./tflint -v /path/to/terraform/config

# Filter by severity level
./tflint -s high /path/to/terraform/config

# Different output formats
./tflint -f json /path/to/terraform/config
./tflint -f sarif -o security-report.sarif /path/to/terraform/config
```

### Advanced Configuration

```bash
# Use configuration file
./tflint --config-file .tflint.yaml /path/to/terraform/config

# Exclude specific patterns
./tflint --exclude "test/*,*.backup.tf" /path/to/terraform/config

# Output to file
./tflint -o security-report.json -f json /path/to/terraform/config
```

### Configuration File Example

Create `.tflint.yaml`:

```yaml
# Exclude patterns (glob syntax)
exclude:
  - "test/*"
  - "*.backup.tf"
  - "vendor/*"

# Override rule severities
severity:
  MISSING_TAGS: "low"
  COST_OPTIMIZATION: "medium"
  AWS_EXPOSED_SECRETS: "critical"

# Custom rules (YAML-based)
custom_rules:
  - name: "CUSTOM_NAMING"
    description: "Resources must follow naming convention"
    severity: "medium"
    pattern: "^[a-z0-9-]+$"
    resource_types: ["aws_instance", "azurerm_virtual_machine"]
```

## Real-World Example Output 📊

```bash
$ ./tflint ../production/terraform/

================================================================================
🔍 Terraform Security Scan Results
================================================================================

📊 Summary:
   Total Issues: 12
   Critical: 7
   High: 1
   Low: 4

🔍 Detailed Issues:
--------------------------------------------------------------------------------

📁 File: ../production/terraform/main.tf
  🚨 [CRITICAL] Hardcoded Azure provider credential: client_secret (line 5)
     Rule: AZURE_EXPOSED_SECRETS
     Description: Azure provider credentials should be stored in variables or environment.

  🚨 [CRITICAL] Hardcoded APP_KEY detected (line 23)
     Rule: AZURE_EXPOSED_SECRETS  
     Description: APP_KEY should not be hardcoded. Use Azure Key Vault or environment variables.

  🚨 [CRITICAL] Hardcoded database connection string with credentials (line 28)
     Rule: AZURE_EXPOSED_SECRETS
     Description: Database connection strings should not contain hardcoded credentials.

  ⚠️ [HIGH] Debug mode enabled in production (line 31)
     Rule: AZURE_WEAK_AUTHENTICATION
     Description: APP_DEBUG should be false in production environments.

================================================================================
❌ Critical and High severity issues found!
```

## Architecture 🏗️

The linter follows a modular architecture designed for maintainability, extensibility, and multi-cloud support:

### Directory Structure

```
go-terraform-linter/
├── cmd/
│   └── linter/
│       └── main.go              # CLI entry point
├── internal/
│   ├── linter/
│   │   └── linter.go           # Core linting engine
│   ├── parser/
│   │   └── parser.go           # Terraform HCL parser with RawValue support
│   ├── report/
│   │   ├── formats/            # Output format handlers
│   │   └── report.go           # Report generation
│   ├── rules/
│   │   ├── custom/
│   │   │   └── yaml.go         # Custom rule support
│   │   ├── security/           # Security rule modules
│   │   │   ├── azure.go        # Azure-specific security rules (14 rules)
│   │   │   ├── aws.go          # AWS-specific security rules (13 rules)
│   │   │   ├── auth.go         # Authentication & IAM rules
│   │   │   ├── best_practices.go # General security practices
│   │   │   ├── cost.go         # Cost optimization rules
│   │   │   ├── network.go      # Network security rules
│   │   │   └── storage.go      # Storage & encryption rules
│   │   ├── engine.go           # Rule execution engine
│   │   └── interface.go        # Rule interface definitions
│   └── types/
│       └── types.go            # Shared data structures with RawValue support
├── examples/
│   └── main.tf                 # Example Terraform files for testing
└── docs/                       # Documentation
```

### Key Components

#### 1. **Enhanced Parser** (`internal/parser/`)
- **HCL Parsing**: Uses `hclsyntax` for robust Terraform parsing
- **RawValue Extraction**: Captures actual string values for secret detection
- **Multi-format Support**: `.tf`, `.tfvars`, and `.tf.json` files
- **Error Resilience**: Continues scanning even with parse errors

#### 2. **Multi-Cloud Rules Engine** (`internal/rules/`)
- **Cloud-Specific Rules**: Separate modules for Azure, AWS, and general rules
- **Pattern-Based Detection**: Advanced regex and string matching for secrets
- **Configurable Severity**: Override rule severities via configuration
- **Extensible Architecture**: Easy to add new cloud providers

#### 3. **Advanced Secret Detection**
- **Hardcoded Credentials**: Azure/AWS provider credentials
- **API Keys & Tokens**: JWT secrets, OAuth tokens, API keys
- **Database Connections**: Connection strings with embedded credentials
- **Application Secrets**: APP_KEY, client secrets, debug settings

## CI/CD Integration 🔄

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - uses: actions/setup-go@v3
      with:
        go-version: '1.18'
    
    - name: Build Terraform Linter
      run: |
        git clone https://github.com/heyimusa/go-terraform-linter.git
        cd go-terraform-linter
        go build -o tflint cmd/linter/main.go
    
    - name: Run Security Scan
      run: |
        ./go-terraform-linter/tflint -f sarif -o security-results.sarif ./terraform/
    
    - name: Upload SARIF results
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: security-results.sarif
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh '''
                    git clone https://github.com/heyimusa/go-terraform-linter.git
                    cd go-terraform-linter
                    go build -o tflint cmd/linter/main.go
                    ./tflint -f json -o security-report.json ../terraform/
                '''
                archiveArtifacts artifacts: 'security-report.json'
                publishHTML([
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: '.',
                    reportFiles: 'security-report.json',
                    reportName: 'Security Scan Report'
                ])
            }
        }
    }
}
```

## Performance 📈

- **Parallel Processing**: Scans multiple files concurrently
- **Memory Efficient**: Minimal memory footprint even for large codebases
- **Fast Execution**: Typical scan times:
  - Small project (10-20 files): < 1 second
  - Medium project (50-100 files): 2-5 seconds
  - Large project (200+ files): 5-15 seconds

## Contributing 🤝

We welcome contributions! Here's how to add new security rules:

### Adding Azure Rules

1. Edit `internal/rules/security/azure.go`
2. Create a new rule struct implementing the `Rule` interface
3. Add pattern-based detection logic
4. Register the rule in `internal/rules/engine.go`

### Adding AWS Rules

1. Edit `internal/rules/security/aws.go`
2. Follow the same pattern as existing AWS rules
3. Use `RawValue` field for secret detection
4. Register in the engine

### Example New Rule

```go
// AzureNewSecurityRule detects a new security issue
type AzureNewSecurityRule struct{}

func (r *AzureNewSecurityRule) GetName() string {
    return "AZURE_NEW_SECURITY"
}

func (r *AzureNewSecurityRule) Check(config *parser.Config) []types.Issue {
    var issues []types.Issue
    
    for _, block := range config.Blocks {
        // Your detection logic here
        if /* condition */ {
            issues = append(issues, types.Issue{
                Rule:        r.GetName(),
                Severity:    "HIGH",
                Message:     "Security issue detected",
                Description: "Detailed description and fix suggestion",
                Line:        block.Range.Start.Line,
            })
        }
    }
    
    return issues
}
```

## License 📄

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments 🙏

- Built with [HashiCorp HCL](https://github.com/hashicorp/hcl) for robust Terraform parsing
- Inspired by security best practices from Azure and AWS documentation
- Community feedback and contributions

## Support 💬

- 🐛 **Issues**: [GitHub Issues](https://github.com/heyimusa/go-terraform-linter/issues)
- 💡 **Feature Requests**: [GitHub Discussions](https://github.com/heyimusa/go-terraform-linter/discussions)
- 📧 **Contact**: [Your Email]

---

**⚡ Start securing your Terraform infrastructure today!**

```bash
git clone https://github.com/heyimusa/go-terraform-linter.git
cd go-terraform-linter
go build -o tflint cmd/linter/main.go
./tflint /path/to/your/terraform/
``` 