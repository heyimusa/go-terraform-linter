# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2024-12-19

### Added - Major Multi-Cloud Security Release 🚀

#### Multi-Cloud Support
- **Azure Security Rules (14 rules)**: Comprehensive Azure-specific security scanning
  - Hardcoded Azure provider credentials detection
  - Public access configuration detection
  - Unencrypted storage identification
  - Weak authentication settings detection
  - Missing resource tags validation
  - Network security misconfigurations

- **AWS Security Rules (13 rules)**: Complete AWS security rule set
  - AWS Access Key and Secret Key detection
  - Public S3 bucket configuration scanning
  - Unencrypted storage detection (EBS, RDS, S3)
  - IAM excessive permissions identification
  - Security group misconfigurations
  - Missing backup configuration detection

#### Advanced Secret Detection
- **Enhanced Parser**: Added `RawValue` field to `Attribute` struct for better secret extraction
- **Pattern-Based Detection**: Advanced regex patterns for:
  - API keys and tokens (20+ character patterns)
  - Database connection strings with embedded credentials
  - JWT secrets and OAuth client secrets
  - Application secrets (APP_KEY, client_secret)
  - Debug mode detection (APP_DEBUG=true)

#### Security Rules Categories
- **Critical Severity (7 rules)**: Exposed secrets, public access, unrestricted ingress
- **High Severity (8 rules)**: Unencrypted storage, weak passwords, excessive permissions
- **Medium Severity (6 rules)**: Missing backup, deprecated resources, open ports
- **Low Severity (4 rules)**: Missing tags, cost optimization

#### Architecture Improvements
- **Modular Rule System**: Separated rules into cloud-specific modules
- **Enhanced Error Handling**: Graceful handling of parse errors
- **Improved Performance**: Parallel processing and efficient memory usage
- **Better Debugging**: Comprehensive debug output for troubleshooting

### Enhanced Features

#### Parser Improvements
- **HCL Syntax Parsing**: Robust parsing using `hclsyntax` package
- **Multi-format Support**: Support for `.tf`, `.tfvars`, and `.tf.json` files
- **Raw Value Extraction**: Capture actual string representations for secret detection
- **Error Resilience**: Continue scanning even when some files fail to parse

#### Reporting Enhancements
- **Colored Output**: Beautiful terminal output with severity-based colors
- **Detailed Descriptions**: Comprehensive issue descriptions and fix suggestions
- **Multiple Formats**: Text, JSON, SARIF, and HTML output formats
- **CI/CD Integration**: SARIF format for GitHub Security tab integration

#### Configuration System
- **YAML/JSON Config**: Support for configuration files with custom rules
- **Severity Overrides**: Ability to override rule severities
- **Exclude Patterns**: Glob-based file exclusion patterns
- **Custom Rules**: Framework for user-defined security rules

### Technical Improvements

#### Code Quality
- **Interface-Based Design**: Clean separation of concerns with rule interfaces
- **Type Safety**: Comprehensive type definitions in `internal/types/`
- **Error Handling**: Robust error handling throughout the codebase
- **Documentation**: Extensive code documentation and examples

#### Performance Optimizations
- **Concurrent Processing**: Parallel file analysis for large codebases
- **Memory Efficiency**: Minimal memory footprint even for large projects
- **Fast Execution**: Optimized parsing and rule execution

### Real-World Validation
- **Production Testing**: Successfully tested on real Azure and AWS Terraform configurations
- **Vulnerability Detection**: Confirmed detection of actual security vulnerabilities:
  - Hardcoded Azure provider credentials
  - Database connection strings with passwords
  - OAuth client secrets
  - Debug mode enabled in production
  - Missing encryption configurations

### Breaking Changes
- **Rule Structure**: Migrated from function-based to struct-based rule implementation
- **Import Paths**: Updated import paths to use proper module structure
- **Configuration Format**: Enhanced configuration file format with more options

### Security Fixes
- **Secret Detection**: Improved detection of various secret patterns
- **False Positive Reduction**: Better pattern matching to reduce false positives
- **Comprehensive Coverage**: Expanded coverage of security misconfigurations

## [1.0.0] - 2024-12-01

### Added - Initial Release
- Basic Terraform file parsing
- General security rules
- Command-line interface
- JSON output format
- Basic error handling

### Features
- **Security Rules**: Initial set of 15 general security rules
- **CLI Interface**: Command-line tool with basic options
- **File Support**: Support for `.tf` files
- **Report Generation**: Basic text and JSON reporting

### Dependencies
- HashiCorp HCL v2 for Terraform parsing
- Cobra for CLI framework
- Color library for terminal output

---

## Migration Guide

### Upgrading from 1.x to 2.x

#### Rule Names
Some rule names have changed to be more specific:
- `EXPOSED_SECRETS` → `AZURE_EXPOSED_SECRETS` / `AWS_EXPOSED_SECRETS`
- `PUBLIC_ACCESS` → `AZURE_PUBLIC_ACCESS` / `AWS_PUBLIC_S3_BUCKET`
- `UNENCRYPTED_STORAGE` → `AZURE_UNENCRYPTED_STORAGE` / `AWS_UNENCRYPTED_STORAGE`

#### Configuration Files
Update your configuration files to use the new format:

```yaml
# Old format (1.x)
rules:
  - EXPOSED_SECRETS
  - PUBLIC_ACCESS

# New format (2.x)
severity:
  AZURE_EXPOSED_SECRETS: "critical"
  AWS_EXPOSED_SECRETS: "critical"
  AZURE_PUBLIC_ACCESS: "high"
  AWS_PUBLIC_S3_BUCKET: "critical"
```

#### Command Line
The CLI interface remains backward compatible, but new options are available:
```bash
# Still works
./tflint /path/to/terraform

# New options
./tflint --config-file .tflint.yaml /path/to/terraform
./tflint --exclude "test/*" /path/to/terraform
```

## Contributors

- [@heyimusa](https://github.com/heyimusa) - Initial development and multi-cloud support
- Community contributors - Bug reports and feature requests

## Acknowledgments

- HashiCorp HCL team for excellent Terraform parsing library
- Azure and AWS security documentation teams
- Open source security community for best practices 