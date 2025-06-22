# 📚 Documentation Index

Welcome to the Go Terraform Linter documentation! This comprehensive guide will help you get started, configure, and effectively use the linter in your Terraform projects.

## 🚀 Quick Start

New to the Go Terraform Linter? Start here:

1. **[Installation Guide](INSTALLATION.md)** - Get up and running quickly
2. **[Usage Guide](USAGE.md)** - Learn the basics and common commands
3. **[Configuration Guide](CONFIGURATION.md)** - Customize the linter for your needs

## 📖 Documentation Structure

### 🏗️ Getting Started
- **[Installation Guide](INSTALLATION.md)** - Complete installation instructions for all platforms
  - Binary installation (recommended)
  - Source installation
  - Docker installation
  - Package managers
  - Troubleshooting installation issues

- **[Usage Guide](USAGE.md)** - Comprehensive usage documentation
  - Basic commands and CLI options
  - Output formats (text, JSON, SARIF, HTML)
  - Filtering and exclusions
  - CI/CD integration examples
  - Advanced usage patterns

### ⚙️ Configuration
- **[Configuration Guide](CONFIGURATION.md)** - Detailed configuration reference
  - Configuration file formats (YAML, JSON, TOML)
  - Rule configuration and customization
  - Provider-specific settings
  - Environment variables
  - Performance tuning

### 📋 Rules and Security
- **[Rules Documentation](RULES.md)** - Complete rules reference
  - AWS rules (45+ rules across 12 services)
  - Azure rules (25+ rules across 8 services)
  - GCP rules (20+ rules across 6 services)
  - Kubernetes rules (15+ rules)
  - Generic rules and custom rule creation

### 🛠️ Development and Integration
- **[Development Guide](DEVELOPMENT.md)** - For contributors and developers
  - Project structure and architecture
  - Development environment setup
  - Adding new rules
  - Testing guidelines
  - Code style and best practices

- **[API Reference](API.md)** - Programmatic usage documentation
  - Core interfaces and types
  - Linter API
  - Configuration API
  - Rules API
  - Report generation API

### 🔧 Support and Troubleshooting
- **[Troubleshooting Guide](TROUBLESHOOTING.md)** - Common issues and solutions
  - Installation problems
  - Configuration errors
  - Runtime issues
  - Performance optimization
  - Debug mode and diagnostics

## 🎯 Use Cases

### Security Teams
- **Automated Security Scanning**: Integrate into CI/CD pipelines for continuous security assessment
- **Compliance Monitoring**: Ensure infrastructure meets security standards and regulations
- **Risk Assessment**: Generate detailed security reports with severity classifications

**Recommended Reading**:
1. [Installation Guide](INSTALLATION.md) → [Rules Documentation](RULES.md) → [CI/CD Integration](USAGE.md#cicd-integration)

### DevOps Engineers
- **Infrastructure Validation**: Catch misconfigurations before deployment
- **Best Practices Enforcement**: Ensure consistent infrastructure patterns
- **Cost Optimization**: Identify expensive or inefficient resource configurations

**Recommended Reading**:
1. [Installation Guide](INSTALLATION.md) → [Usage Guide](USAGE.md) → [Configuration Guide](CONFIGURATION.md)

### Platform Engineers
- **Policy as Code**: Define and enforce organizational infrastructure policies
- **Multi-Cloud Governance**: Consistent security across AWS, Azure, and GCP
- **Custom Rule Development**: Create organization-specific validation rules

**Recommended Reading**:
1. [Development Guide](DEVELOPMENT.md) → [API Reference](API.md) → [Rules Documentation](RULES.md#custom-rules)

### Developers
- **Local Development**: Validate Terraform before committing changes
- **IDE Integration**: Real-time feedback during infrastructure development
- **Learning Tool**: Understand security best practices through rule explanations

**Recommended Reading**:
1. [Installation Guide](INSTALLATION.md) → [Usage Guide](USAGE.md) → [Troubleshooting Guide](TROUBLESHOOTING.md)

## 🏃‍♂️ Quick Reference

### Essential Commands
```bash
# Install (Linux/macOS)
curl -L https://github.com/heyimusa/go-terraform-linter/releases/latest/download/terraform-linter-linux-amd64 -o terraform-linter
chmod +x terraform-linter && sudo mv terraform-linter /usr/local/bin/

# Basic usage
terraform-linter .                    # Scan current directory
terraform-linter --severity high .   # Only high/critical issues
terraform-linter --format json .     # JSON output
terraform-linter --output report.html --format html .  # HTML report

# Configuration
terraform-linter --config custom-config.yml .
terraform-linter --list-rules         # Show available rules
terraform-linter --show-config        # Show effective configuration
```

### Common Configuration
```yaml
# .terraform-linter.yml
version: "1.0"
severity: "medium"
format: "text"
parallel: 4

include: ["**/*.tf", "**/*.tfvars"]
exclude: ["**/test/**", "**/.terraform/**"]

rules:
  enabled: ["aws-*", "security-*"]
  disabled: ["aws-s3-bucket-versioning"]
  
  settings:
    aws-s3-bucket-public-access-block:
      exceptions: ["public-website-*"]
```

### Integration Examples
```yaml
# GitHub Actions
- name: Terraform Security Scan
  run: |
    terraform-linter --format sarif --output results.sarif .
    
# Docker
docker run --rm -v $(pwd):/workspace \
  ghcr.io/heyimusa/go-terraform-linter:latest /workspace
```

## 📊 Feature Matrix

| Feature | Status | Documentation |
|---------|--------|---------------|
| **Multi-Cloud Support** | ✅ | [Rules Documentation](RULES.md) |
| AWS (45+ rules) | ✅ | [AWS Rules](RULES.md#aws-rules) |
| Azure (25+ rules) | ✅ | [Azure Rules](RULES.md#azure-rules) |
| GCP (20+ rules) | ✅ | [GCP Rules](RULES.md#gcp-rules) |
| Kubernetes (15+ rules) | ✅ | [Kubernetes Rules](RULES.md#kubernetes-rules) |
| **Output Formats** | ✅ | [Usage Guide](USAGE.md#output-formats) |
| Text | ✅ | [Usage Guide](USAGE.md#text-format-default) |
| JSON | ✅ | [Usage Guide](USAGE.md#json-format) |
| SARIF | ✅ | [Usage Guide](USAGE.md#sarif-format) |
| HTML | ✅ | [Usage Guide](USAGE.md#html-format) |
| **CI/CD Integration** | ✅ | [Usage Guide](USAGE.md#cicd-integration) |
| GitHub Actions | ✅ | [GitHub Actions Example](USAGE.md#github-actions) |
| GitLab CI | ✅ | [GitLab CI Example](USAGE.md#gitlab-ci) |
| Jenkins | ✅ | [Jenkins Example](USAGE.md#jenkins-pipeline) |
| **Performance** | ✅ | [Configuration Guide](CONFIGURATION.md#performance-settings) |
| Parallel Processing | ✅ | [Performance Tuning](CONFIGURATION.md#performance-tuning) |
| Caching | ✅ | [Cache Configuration](CONFIGURATION.md#cache-configuration) |
| **Customization** | ✅ | [Configuration Guide](CONFIGURATION.md) |
| Custom Rules | ✅ | [Custom Rules](RULES.md#custom-rules) |
| Rule Configuration | ✅ | [Rule Configuration](CONFIGURATION.md#rule-configuration) |
| **API Integration** | ✅ | [API Reference](API.md) |
| Programmatic Usage | ✅ | [Linter API](API.md#linter-api) |
| Custom Formatters | ✅ | [Report API](API.md#report-api) |

## 🔗 External Resources

### Terraform Security
- [Terraform Security Best Practices](https://www.terraform.io/docs/cloud/guides/recommended-practices/index.html)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [OWASP Infrastructure as Code Security](https://owasp.org/www-project-devsecops-guideline/)

### Cloud Provider Security
- [AWS Security Best Practices](https://aws.amazon.com/architecture/security-identity-compliance/)
- [Azure Security Documentation](https://docs.microsoft.com/en-us/azure/security/)
- [GCP Security Best Practices](https://cloud.google.com/security/best-practices)

### DevSecOps Tools
- [Terraform](https://www.terraform.io/)
- [Checkov](https://www.checkov.io/)
- [tfsec](https://github.com/aquasecurity/tfsec)
- [Terrascan](https://github.com/accurics/terrascan)

## 🤝 Community and Support

### Getting Help
- **Documentation**: Start with this documentation suite
- **GitHub Issues**: [Report bugs or request features](https://github.com/heyimusa/go-terraform-linter/issues)
- **GitHub Discussions**: [Ask questions and share ideas](https://github.com/heyimusa/go-terraform-linter/discussions)
- **Troubleshooting**: Check the [Troubleshooting Guide](TROUBLESHOOTING.md)

### Contributing
- **Development**: See the [Development Guide](DEVELOPMENT.md)
- **Rules**: Learn to [create custom rules](RULES.md#custom-rules)
- **Documentation**: Help improve these docs
- **Testing**: Report issues and help with testing

### Stay Updated
- **Releases**: Watch the [GitHub repository](https://github.com/heyimusa/go-terraform-linter) for updates
- **Changelog**: Check [CHANGELOG.md](../CHANGELOG.md) for release notes
- **Security**: Review [SECURITY.md](../SECURITY.md) for security updates

## 📈 Roadmap

### Current Version (1.0)
- ✅ Multi-cloud rule support (AWS, Azure, GCP, Kubernetes)
- ✅ Multiple output formats
- ✅ CI/CD integration
- ✅ Performance optimization
- ✅ Comprehensive documentation

### Upcoming Features
- 🔄 Rule marketplace and community rules
- 🔄 IDE plugins (VS Code, IntelliJ)
- 🔄 Web dashboard and reporting
- 🔄 Machine learning-based rule suggestions
- 🔄 Policy as Code integration

### Long-term Vision
- 🎯 AI-powered infrastructure analysis
- 🎯 Real-time infrastructure monitoring
- 🎯 Advanced compliance reporting
- 🎯 Multi-language support (Python, Java, etc.)

---

## 📝 Documentation Feedback

Help us improve this documentation:

- **Found an error?** [Open an issue](https://github.com/heyimusa/go-terraform-linter/issues/new?template=documentation.md)
- **Missing information?** [Request documentation](https://github.com/heyimusa/go-terraform-linter/issues/new?template=documentation-request.md)
- **Want to contribute?** See our [Contributing Guide](../CONTRIBUTING.md)

**Last Updated**: December 2024 | **Version**: 1.0.0 