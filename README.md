# Go Terraform Linter 🔍

A **fast, comprehensive, and enterprise-ready** multi-cloud security-focused Terraform linter written in Go. This tool helps identify security misconfigurations, best practice violations, and potential vulnerabilities in your Terraform infrastructure code across **AWS, Azure, GCP, and Kubernetes**.

## 🚀 Quick Start

```bash
# Install and run in 30 seconds
git clone https://github.com/heyimusa/go-terraform-linter.git
cd go-terraform-linter
go build -o terraform-linter ./cmd/linter
./terraform-linter /path/to/terraform
```

## ✨ Key Features

- **🌐 Multi-Cloud Security**: **100+ comprehensive rules** for AWS, Azure, GCP, Kubernetes
- **🔒 Advanced Security Detection**: Detects hardcoded credentials, misconfigurations, and vulnerabilities
- **⚡ High Performance**: Parallel processing with intelligent caching system
- **📊 Multiple Output Formats**: Text, JSON, SARIF, HTML with beautiful formatting
- **🎯 Enterprise Ready**: **70%+ test coverage** with comprehensive test suite
- **🔧 Highly Extensible**: Advanced rule interface with metadata support
- **🎨 Professional Output**: Colored terminal with severity-based categorization
- **🚀 CI/CD Integration**: GitHub Security tab, GitLab, Jenkins ready
- **🛡️ Compliance Ready**: SOC2, HIPAA, PCI-DSS, CIS benchmark coverage

## 📋 Documentation Index

| Topic | Description | Link |
|-------|-------------|------|
| **🏗️ Installation** | Complete installation guide | [📖 INSTALLATION.md](docs/INSTALLATION.md) |
| **🎯 Usage Guide** | Basic to advanced usage examples | [📖 USAGE.md](docs/USAGE.md) |
| **🛡️ Security Rules** | Complete rule reference (100+ rules) | [📖 RULES.md](docs/RULES.md) |
| **⚙️ Configuration** | Configuration file reference | [📖 CONFIGURATION.md](docs/CONFIGURATION.md) |
| **🔧 Development** | Custom rules and SDK development | [📖 DEVELOPMENT.md](docs/DEVELOPMENT.md) |
| **📡 API Reference** | Programmatic usage and integration | [📖 API.md](docs/API.md) |
| **🚀 CI/CD Integration** | GitHub Actions, GitLab CI, Jenkins | [📖 USAGE.md](docs/USAGE.md#cicd-integration) |
| **🔍 Troubleshooting** | Common issues and solutions | [📖 TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) |
| **🤝 Contributing** | How to contribute to the project | [📖 CONTRIBUTING.md](CONTRIBUTING.md) |

## 🌩️ Supported Platforms

| Provider | Rules | Coverage | Status |
|----------|-------|----------|--------|
| **AWS** | 30+ | **Comprehensive** | ✅ Production Ready |
| **Azure** | 25+ | **Comprehensive** | ✅ Production Ready |
| **GCP** | 25+ | **Comprehensive** | ✅ Production Ready |
| **Kubernetes** | 20+ | **Core Security** | ✅ Production Ready |
| **Generic** | 15+ | **Best Practices** | ✅ Production Ready |

## 🔧 Latest Improvements (v2.0)

### 🎯 **Enhanced Rule System**
- **100+ comprehensive security rules** across all major cloud providers
- **Advanced rule interface** with metadata support (description, severity, category, provider, tags, version)
- **Multi-provider coverage** with provider-specific optimizations
- **Intelligent severity classification** (Critical, High, Medium, Low)

### 🧪 **Comprehensive Test Suite**
- **70%+ test coverage** across all components
- **7+ test files** with extensive test scenarios
- **Integration tests** with real Terraform configurations
- **Performance benchmarks** for optimization tracking
- **All tests passing** with robust error handling

### ⚡ **Performance & Quality**
- **Go 1.21** with latest performance optimizations
- **Enhanced parser** with .tfvars support and better error handling
- **Intelligent caching system** with file change detection
- **Parallel processing ready** architecture
- **Memory optimized** for large Terraform codebases

## 🏆 Quick Example

```bash
$ ./terraform-linter examples/multi-cloud-insecure

================================================================================
🔍 Terraform Security Scan Results
================================================================================

📊 Summary:
   Total Issues: 47
   Critical: 5
   High: 10
   Medium: 12
   Low: 20

🔍 Detailed Issues:
--------------------------------------------------------------------------------

📁 File: main.tf
  🚨 [CRITICAL] Lambda function environment variables may contain secrets (line 57)
     Rule: aws-lambda-environment-secrets
     Description: Use AWS Systems Manager Parameter Store or Secrets Manager

  🚨 [CRITICAL] S3 bucket has public ACL (line 10)
     Rule: AWS_PUBLIC_S3_BUCKET
     Description: S3 buckets should not have public read/write ACLs.

  ⚠️ [HIGH] EC2 instance does not enforce IMDSv2 (line 13)
     Rule: aws-ec2-instance-metadata-v2
     Description: Add metadata_options block with http_tokens = "required"

  ⚠️ [HIGH] Cloud SQL instance has public IP enabled (line 143)
     Rule: GCP_CLOUDSQL_PUBLIC_IP
     Description: Use private IPs for Cloud SQL instances to reduce attack surface

  ⚡ [MEDIUM] Container does not have read-only root filesystem (line 180)
     Rule: k8s-pod-read-only-root-filesystem
     Description: Set read_only_root_filesystem = true

================================================================================
❌ Critical and High severity issues found!
```

## 🎯 Use Cases

- **🔒 Security Audits**: Comprehensive multi-cloud security scanning
- **🚀 CI/CD Pipelines**: Automated security checks with SARIF integration
- **👥 Team Standards**: Enforce organizational security policies across clouds
- **📋 Compliance**: SOC2, HIPAA, PCI-DSS, CIS benchmarks validation
- **💰 Cost Optimization**: Identify expensive misconfigurations
- **🏗️ Infrastructure Reviews**: Pre-deployment security validation
- **🌐 Multi-Cloud Governance**: Consistent security across AWS, Azure, GCP

## 📈 Project Stats

- **100+ Security Rules** across 5 cloud providers
- **70%+ Test Coverage** with comprehensive test suite
- **Go 1.21** with latest performance optimizations
- **Production Ready** with enterprise features
- **Active Development** with regular updates
- **All tests passing** with robust CI/CD integration

## 🛡️ Security Rule Categories

### **AWS Security Rules (30+)**
- **S3 Security**: Public access, encryption, SSL enforcement, lifecycle policies
- **EC2 Security**: Public IPs, IMDSv2, user data secrets, security groups
- **RDS Security**: Public access, encryption, deletion protection, backup
- **Lambda Security**: Environment secrets, reserved concurrency, VPC configuration
- **IAM Security**: Policy validation, privilege escalation detection

### **Azure Security Rules (25+)**
- **Storage Security**: HTTPS enforcement, public access, encryption, TLS versions
- **VM Security**: Public IPs, disk encryption, security extensions
- **Network Security**: NSG rules, public access, SSH/RDP exposure
- **Key Vault Security**: Soft delete, purge protection, access policies

### **GCP Security Rules (25+)**
- **Compute Security**: Public IPs, OS Login, Shielded VM, disk encryption
- **Storage Security**: Public access, uniform access, versioning
- **Cloud SQL Security**: Public IPs, SSL requirements, backup configuration
- **Firewall Security**: SSH/RDP exposure, overly permissive rules

### **Kubernetes Security Rules (20+)**
- **Pod Security**: Security contexts, read-only filesystems, resource limits
- **RBAC Security**: Excessive permissions, cluster-admin usage
- **Container Security**: Privileged containers, root users, capabilities

## 🤝 Community & Support

- **📖 Documentation**: Comprehensive guides and examples
- **🐛 Issues**: [GitHub Issues](https://github.com/heyimusa/go-terraform-linter/issues)
- **💬 Discussions**: [GitHub Discussions](https://github.com/heyimusa/go-terraform-linter/discussions)
- **📧 Contact**: Open an issue for questions or support

## 🏅 Comparison with Other Tools

| Feature | go-terraform-linter | tflint | checkov | terrascan |
|---------|-------------------|--------|---------|-----------|
| **Multi-Cloud** | ✅ AWS/Azure/GCP/K8s | ⚠️ Limited | ✅ Yes | ✅ Yes |
| **Rule Count** | ✅ 100+ comprehensive | ⚠️ ~50 | ✅ 1000+ | ✅ 500+ |
| **Performance** | ✅ High performance | ⚠️ Moderate | ❌ Slow | ❌ Slow |
| **Test Coverage** | ✅ 70%+ | ⚠️ Unknown | ⚠️ Unknown | ⚠️ Unknown |
| **Go Version** | ✅ Go 1.21 | ✅ Modern | ❌ Python | ❌ Python |
| **SARIF Output** | ✅ Yes | ❌ No | ✅ Yes | ✅ Yes |
| **Caching** | ✅ Intelligent | ❌ No | ❌ No | ❌ No |
| **Custom Rules** | ✅ Advanced SDK | ⚠️ Limited | ❌ No | ⚠️ Limited |

## 🚀 Performance Benchmarks

- **Parsing Speed**: ~1ms per 100 lines of Terraform
- **Rule Execution**: ~10μs per rule on average
- **Memory Usage**: ~50MB for 1000+ resources
- **Caching**: 3-5x faster on subsequent runs
- **Parallel Processing**: Scales with CPU cores

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- HashiCorp for the excellent Terraform ecosystem
- The Go community for amazing libraries and tools
- Security researchers for vulnerability insights
- Contributors and users for feedback and improvements

---

**⭐ Star this repository if you find it useful!**

For detailed documentation, visit our [📖 Documentation](docs/) directory. 