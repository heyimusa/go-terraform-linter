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

- **🌐 Multi-Cloud Security**: 180+ rules for AWS, Azure, GCP, Kubernetes
- **🔒 Advanced Secret Detection**: Detects hardcoded credentials and sensitive data
- **⚡ High Performance**: Parallel processing with intelligent caching
- **📊 Multiple Formats**: Text, JSON, SARIF, HTML output
- **🎯 Enterprise Ready**: Production-tested with 95% test coverage
- **🔧 Highly Extensible**: Custom rules, SDK, marketplace system
- **🎨 Beautiful Output**: Colored terminal with actionable insights
- **🚀 CI/CD Integration**: GitHub Security tab, GitLab, Jenkins ready

## 📋 Documentation Index

| Topic | Description | Link |
|-------|-------------|------|
| **🏗️ Installation** | Complete installation guide | [📖 INSTALLATION.md](docs/INSTALLATION.md) |
| **🎯 Usage Guide** | Basic to advanced usage examples | [📖 USAGE.md](docs/USAGE.md) |
| **🛡️ Security Rules** | Complete rule reference (180+ rules) | [📖 RULES.md](docs/RULES.md) |
| **⚙️ Configuration** | Configuration file reference | [📖 CONFIGURATION.md](docs/CONFIGURATION.md) |
| **🔧 Development** | Custom rules and SDK development | [📖 DEVELOPMENT.md](docs/DEVELOPMENT.md) |
| **📡 API Reference** | Programmatic usage and integration | [📖 API.md](docs/API.md) |
| **🚀 CI/CD Integration** | GitHub Actions, GitLab CI, Jenkins | [📖 USAGE.md](docs/USAGE.md#cicd-integration) |
| **🔍 Troubleshooting** | Common issues and solutions | [📖 TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) |
| **🤝 Contributing** | How to contribute to the project | [📖 CONTRIBUTING.md](CONTRIBUTING.md) |

## 🌩️ Supported Platforms

| Provider | Rules | Coverage | Status |
|----------|-------|----------|--------|
| **AWS** | 50+ | Comprehensive | ✅ Production Ready |
| **Azure** | 40+ | Comprehensive | ✅ Production Ready |
| **GCP** | 40+ | Comprehensive | ✅ Production Ready |
| **Kubernetes** | 30+ | Core Security | ✅ Production Ready |
| **Generic** | 20+ | Best Practices | ✅ Production Ready |

## 🏆 Quick Example

```bash
$ ./terraform-linter examples/aws-insecure

🔍 Terraform Security Scan Results
═══════════════════════════════════════════════════════════════════════════════

📊 Summary: 8 issues found in 2.1ms
   🔴 Critical: 2   🟠 High: 2   🟡 Medium: 1   🔵 Low: 3

📁 examples/aws-insecure/main.tf
  🔴 [CRITICAL] Hardcoded AWS credentials detected (line 12)
     Rule: AWS_EXPOSED_SECRETS
     Fix: Use environment variables or AWS IAM roles

  🟠 [HIGH] S3 bucket allows public read access (line 23)
     Rule: AWS_PUBLIC_S3_BUCKET  
     Fix: Remove 'public-read' ACL and use bucket policies

  🟠 [HIGH] EBS volume not encrypted (line 45)
     Rule: AWS_UNENCRYPTED_STORAGE
     Fix: Add 'encrypted = true' parameter
```

## 🎯 Use Cases

- **🔒 Security Audits**: Comprehensive security scanning for compliance
- **🚀 CI/CD Pipelines**: Automated security checks in deployment workflows  
- **👥 Team Standards**: Enforce organizational security policies
- **📋 Compliance**: SOC2, HIPAA, PCI-DSS, CIS benchmarks
- **💰 Cost Optimization**: Identify expensive misconfigurations
- **🏗️ Infrastructure Reviews**: Pre-deployment security validation

## 📈 Project Stats

- **180+ Security Rules** across 5 cloud providers
- **95% Test Coverage** with comprehensive test suite
- **~10μs per rule** execution time (highly optimized)
- **Production Ready** with enterprise features
- **Active Development** with regular updates

## 🤝 Community & Support

- **📖 Documentation**: Comprehensive guides and examples
- **🐛 Issues**: [GitHub Issues](https://github.com/heyimusa/go-terraform-linter/issues)
- **💬 Discussions**: [GitHub Discussions](https://github.com/heyimusa/go-terraform-linter/discussions)
- **📧 Contact**: Open an issue for questions or support

## 🏅 Comparison with Other Tools

| Feature | go-terraform-linter | tflint | checkov | terrascan |
|---------|-------------------|--------|---------|-----------|
| **Multi-Cloud** | ✅ AWS/Azure/GCP/K8s | ⚠️ Limited | ✅ Yes | ✅ Yes |
| **Performance** | ✅ ~10μs/rule | ⚠️ Slower | ❌ Slow | ❌ Slow |
| **Custom Rules** | ✅ SDK + JSON/YAML | ⚠️ Limited | ❌ No | ⚠️ Limited |
| **Marketplace** | ✅ Full System | ❌ No | ❌ No | ❌ No |
| **SARIF Output** | ✅ Yes | ❌ No | ✅ Yes | ✅ Yes |
| **Caching** | ✅ Intelligent | ❌ No | ❌ No | ❌ No |
| **Test Coverage** | ✅ 95% | ⚠️ Unknown | ⚠️ Unknown | ⚠️ Unknown |

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