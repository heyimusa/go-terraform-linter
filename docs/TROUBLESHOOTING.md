# 🔧 Troubleshooting Guide

This guide helps you diagnose and resolve common issues with the Go Terraform Linter.

## 📋 Table of Contents

- [Installation Issues](#installation-issues)
- [Configuration Problems](#configuration-problems)
- [Runtime Errors](#runtime-errors)
- [Performance Issues](#performance-issues)
- [Rule-Specific Issues](#rule-specific-issues)
- [CI/CD Integration Issues](#cicd-integration-issues)
- [Debug Mode](#debug-mode)
- [Getting Help](#getting-help)

## 🏗️ Installation Issues

### Go Version Compatibility

**Problem**: `go: module requires Go 1.21 or later`
```bash
go version
# go version go1.18.1 linux/amd64
```

**Solution**: Upgrade Go to version 1.21 or later
```bash
# Download and install Go 1.21
wget https://go.dev/dl/go1.21.13.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.21.13.linux-amd64.tar.gz

# Update PATH
echo 'export PATH=/usr/local/go/bin:$PATH' >> ~/.bashrc
source ~/.bashrc

# Verify installation
go version
```

### Binary Download Issues

**Problem**: `curl: (22) The requested URL returned error: 404`

**Solution**: Check the correct release URL
```bash
# Check available releases
curl -s https://api.github.com/repos/heyimusa/go-terraform-linter/releases/latest | grep browser_download_url

# Download correct binary for your platform
curl -L https://github.com/heyimusa/go-terraform-linter/releases/latest/download/terraform-linter-linux-amd64 -o terraform-linter
```

### Permission Denied

**Problem**: `bash: ./terraform-linter: Permission denied`

**Solution**: Make the binary executable
```bash
chmod +x terraform-linter

# Or install system-wide
sudo mv terraform-linter /usr/local/bin/
```

### Command Not Found

**Problem**: `terraform-linter: command not found`

**Solutions**:
```bash
# Option 1: Add to PATH
export PATH=$PATH:/path/to/terraform-linter
echo 'export PATH=$PATH:/path/to/terraform-linter' >> ~/.bashrc

# Option 2: Use full path
/usr/local/bin/terraform-linter --help

# Option 3: Create symlink
sudo ln -s /path/to/terraform-linter /usr/local/bin/terraform-linter
```

## ⚙️ Configuration Problems

### Configuration File Not Found

**Problem**: `Error: configuration file not found`

**Solution**: Create or specify configuration file
```bash
# Create default configuration
cat > .terraform-linter.yml << EOF
version: "1.0"
severity: "medium"
format: "text"
include: ["**/*.tf", "**/*.tfvars"]
exclude: ["**/.terraform/**"]
EOF

# Or specify config path
terraform-linter --config /path/to/config.yml .
```

### Invalid Configuration Format

**Problem**: `Error: invalid configuration format`

**Solution**: Validate YAML syntax
```bash
# Check YAML syntax
python -c "import yaml; yaml.safe_load(open('.terraform-linter.yml'))"

# Or use online YAML validator
# Fix common issues:
# - Incorrect indentation
# - Missing quotes around special characters
# - Invalid YAML structure
```

### Rule Configuration Errors

**Problem**: `Error: unknown rule 'aws-s3-invalid-rule'`

**Solution**: Check available rules
```bash
# List all available rules
terraform-linter --list-rules

# Check rule name spelling
terraform-linter --list-rules | grep s3

# Correct configuration
rules:
  enabled:
    - "aws-s3-bucket-public-access-block"  # Correct name
```

## 🚨 Runtime Errors

### Parser Errors

**Problem**: `Error parsing Terraform file: syntax error`

**Solutions**:
```bash
# Validate Terraform syntax first
terraform validate

# Check specific file
terraform fmt -check main.tf

# Skip problematic files
terraform-linter --exclude "**/problematic-file.tf" .
```

### Memory Issues

**Problem**: `fatal error: runtime: out of memory`

**Solutions**:
```bash
# Reduce parallel workers
terraform-linter --parallel 2 .

# Exclude large directories
terraform-linter --exclude "**/.terraform/**" --exclude "**/node_modules/**" .

# Process files in batches
find . -name "*.tf" -not -path "**/.terraform/**" | head -100 | xargs terraform-linter

# Increase system memory or use swap
```

### Timeout Errors

**Problem**: `Error: timeout processing file main.tf`

**Solutions**:
```bash
# Increase timeout
terraform-linter --timeout 120 .

# Skip large files
terraform-linter --exclude "**/large-file.tf" .

# Check file for infinite loops or complex expressions
```

### File Access Errors

**Problem**: `Error: permission denied reading file`

**Solutions**:
```bash
# Check file permissions
ls -la *.tf

# Fix permissions
chmod 644 *.tf

# Run with appropriate user
sudo -u terraform-user terraform-linter .
```

## 🐌 Performance Issues

### Slow Scanning

**Problem**: Linter takes too long to complete

**Solutions**:
```bash
# Increase parallel workers (if you have CPU cores available)
terraform-linter --parallel 8 .

# Enable caching
terraform-linter --cache .

# Exclude unnecessary directories
terraform-linter --exclude "**/test/**" --exclude "**/.terraform/**" .

# Use specific rules only
terraform-linter --rules "aws-s3-*,aws-ec2-*" .
```

### High Memory Usage

**Problem**: Linter consumes too much memory

**Solutions**:
```bash
# Reduce parallel workers
terraform-linter --parallel 1 .

# Process smaller batches
terraform-linter --include "modules/**/*.tf" .
terraform-linter --include "environments/**/*.tf" .

# Disable caching if memory is limited
terraform-linter --cache=false .
```

### Cache Issues

**Problem**: Stale cache results

**Solutions**:
```bash
# Clear cache
rm -rf .terraform-linter-cache/

# Disable cache temporarily
terraform-linter --cache=false .

# Set shorter cache TTL
terraform-linter --cache-ttl 1h .
```

## 📋 Rule-Specific Issues

### False Positives

**Problem**: Rule incorrectly flags valid configuration

**Solutions**:
```yaml
# Add exceptions in configuration
rules:
  settings:
    aws-s3-bucket-public-access-block:
      exceptions:
        - "public-website-*"
        - "cdn-assets-*"

# Or disable the rule temporarily
rules:
  disabled:
    - "aws-s3-bucket-public-access-block"
```

### Missing Rules

**Problem**: Expected rule not running

**Solutions**:
```bash
# Check if rule exists
terraform-linter --list-rules | grep "rule-name"

# Check rule configuration
terraform-linter --show-config

# Enable rule explicitly
rules:
  enabled:
    - "aws-s3-bucket-encryption"
```

### Rule Configuration Not Applied

**Problem**: Rule settings not taking effect

**Solutions**:
```bash
# Verify configuration is loaded
terraform-linter --show-config

# Check configuration file path
terraform-linter --config .terraform-linter.yml --show-config

# Validate YAML structure
```

## 🔄 CI/CD Integration Issues

### GitHub Actions Failures

**Problem**: Linter fails in GitHub Actions

**Solutions**:
```yaml
# .github/workflows/terraform-lint.yml
- name: Install Terraform Linter
  run: |
    curl -L https://github.com/heyimusa/go-terraform-linter/releases/latest/download/terraform-linter-linux-amd64 -o terraform-linter
    chmod +x terraform-linter
    sudo mv terraform-linter /usr/local/bin/
    
    # Verify installation
    terraform-linter --version

# Add error handling
- name: Run Terraform Linter
  run: |
    terraform-linter . || echo "Linter found issues"
  continue-on-error: true
```

### Docker Issues

**Problem**: Docker container fails to run

**Solutions**:
```bash
# Check Docker image
docker pull ghcr.io/heyimusa/go-terraform-linter:latest

# Run with proper volume mounting
docker run --rm -v $(pwd):/workspace ghcr.io/heyimusa/go-terraform-linter:latest /workspace

# Check container logs
docker run --rm -v $(pwd):/workspace ghcr.io/heyimusa/go-terraform-linter:latest /workspace --verbose
```

### Permission Issues in CI

**Problem**: Permission denied in CI environment

**Solutions**:
```bash
# In CI script, ensure proper permissions
chmod -R 755 .
terraform-linter .

# Or run as specific user
docker run --rm --user $(id -u):$(id -g) -v $(pwd):/workspace terraform-linter /workspace
```

## 🔍 Debug Mode

### Enable Debug Logging

```bash
# Enable verbose output
terraform-linter --verbose .

# Enable debug mode
export TF_LINTER_DEBUG=true
terraform-linter .

# Save debug output to file
terraform-linter --verbose . 2>&1 | tee debug.log
```

### Debug Configuration

```yaml
# Add to .terraform-linter.yml
advanced:
  logging:
    level: "debug"
    format: "json"
    file: "terraform-linter-debug.log"
```

### Debug Specific Issues

```bash
# Debug parser issues
terraform-linter --verbose --include "problematic-file.tf" .

# Debug rule execution
terraform-linter --verbose --rules "specific-rule" .

# Debug configuration loading
terraform-linter --show-config --verbose
```

## 📊 Common Error Messages

### `Error: failed to parse HCL`

**Cause**: Invalid Terraform syntax
**Solution**: Run `terraform validate` first

### `Error: unknown provider`

**Cause**: Rule references unsupported provider
**Solution**: Check supported providers or disable rule

### `Error: rule not found`

**Cause**: Typo in rule name or rule doesn't exist
**Solution**: Use `--list-rules` to see available rules

### `Error: configuration validation failed`

**Cause**: Invalid configuration format
**Solution**: Validate YAML/JSON syntax

### `Error: cache corruption detected`

**Cause**: Corrupted cache files
**Solution**: Clear cache with `rm -rf .terraform-linter-cache/`

## 🆘 Getting Help

### Collect Debug Information

Before asking for help, collect this information:

```bash
# System information
echo "OS: $(uname -a)"
echo "Go version: $(go version)"
echo "Linter version: $(terraform-linter --version)"

# Configuration
terraform-linter --show-config

# Debug output
terraform-linter --verbose . 2>&1 | head -50
```

### Create Minimal Reproduction

Create a minimal example that reproduces the issue:

```bash
# Create test directory
mkdir terraform-linter-issue
cd terraform-linter-issue

# Create minimal Terraform file
cat > main.tf << EOF
resource "aws_s3_bucket" "test" {
  bucket = "test-bucket"
}
EOF

# Create minimal configuration
cat > .terraform-linter.yml << EOF
version: "1.0"
severity: "low"
EOF

# Test with minimal setup
terraform-linter .
```

### Where to Get Help

1. **Documentation**: Check all docs in the `docs/` directory
2. **GitHub Issues**: Search existing issues or create new one
3. **Discussions**: Use GitHub Discussions for questions
4. **Community**: Join community forums or chat

### Issue Report Template

When creating an issue, include:

```markdown
## Environment
- OS: [e.g., Ubuntu 20.04]
- Go version: [e.g., 1.21.0]
- Linter version: [e.g., 1.0.0]

## Expected Behavior
[What you expected to happen]

## Actual Behavior
[What actually happened]

## Steps to Reproduce
1. [First step]
2. [Second step]
3. [Third step]

## Configuration
```yaml
[Your .terraform-linter.yml content]
```

## Terraform Files
```hcl
[Minimal Terraform configuration that reproduces the issue]
```

## Debug Output
```
[Output from terraform-linter --verbose .]
```
```

### Performance Profiling

For performance issues:

```bash
# CPU profiling
go tool pprof terraform-linter cpu.prof

# Memory profiling
go tool pprof terraform-linter mem.prof

# Generate profiles
terraform-linter --cpuprofile=cpu.prof --memprofile=mem.prof .
```

---

**Additional Resources**:
- [Installation Guide](INSTALLATION.md)
- [Configuration Guide](CONFIGURATION.md) 
- [Usage Examples](USAGE.md)
- [GitHub Issues](https://github.com/heyimusa/go-terraform-linter/issues) 