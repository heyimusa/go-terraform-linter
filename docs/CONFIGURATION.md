# ⚙️ Configuration Guide

This guide covers all configuration options for the Go Terraform Linter, including file formats, rule customization, and advanced settings.

## 📋 Table of Contents

- [Configuration Files](#configuration-files)
- [Configuration Format](#configuration-format)
- [General Settings](#general-settings)
- [Rule Configuration](#rule-configuration)
- [Output Configuration](#output-configuration)
- [Performance Settings](#performance-settings)
- [Provider Settings](#provider-settings)
- [Environment Variables](#environment-variables)
- [Examples](#examples)

## 📁 Configuration Files

### File Discovery
The linter searches for configuration files in this order:

1. **Command line**: `--config /path/to/config.yml`
2. **Current directory**: `.terraform-linter.yml` or `.terraform-linter.yaml`
3. **Current directory**: `terraform-linter.yml` or `terraform-linter.yaml`
4. **Home directory**: `$HOME/.terraform-linter.yml`
5. **Global**: `/etc/terraform-linter/config.yml`

### Supported Formats
- **YAML**: `.yml` or `.yaml` (recommended)
- **JSON**: `.json`
- **TOML**: `.toml`

## 📝 Configuration Format

### Complete YAML Example
```yaml
# .terraform-linter.yml
version: "1.0"

# ============================================================================
# GENERAL SETTINGS
# ============================================================================
severity: "medium"              # Minimum severity: low, medium, high, critical
format: "text"                  # Output format: text, json, sarif, html
verbose: false                  # Enable verbose logging
quiet: false                    # Suppress all output except errors
parallel: 4                     # Number of parallel workers (0 = auto)
timeout: 30                     # Timeout per file in seconds

# ============================================================================
# FILE PATTERNS
# ============================================================================
include:
  - "**/*.tf"                   # Include Terraform files
  - "**/*.tfvars"               # Include variable files
  - "**/*.tf.json"              # Include JSON Terraform files

exclude:
  - "**/test/**"                # Exclude test directories
  - "**/.terraform/**"          # Exclude Terraform cache
  - "**/examples/**"            # Exclude example directories
  - "**/modules/third-party/**" # Exclude third-party modules
  - "**/*.backup.tf"            # Exclude backup files

# ============================================================================
# RULES CONFIGURATION
# ============================================================================
rules:
  # Global rule settings
  enabled:
    - "aws-*"                   # Enable all AWS rules
    - "azure-compute-*"         # Enable Azure compute rules
    - "gcp-security-*"          # Enable GCP security rules
    - "kubernetes-*"            # Enable Kubernetes rules
  
  disabled:
    - "aws-s3-bucket-versioning"        # Disable specific rule
    - "azure-storage-account-https"     # Disable for legacy compatibility
    - "gcp-compute-disk-encryption"     # Disable for cost reasons
  
  # Rule-specific settings
  settings:
    # AWS S3 Configuration
    aws-s3-bucket-public-access-block:
      severity: "high"
      exceptions:
        - "public-website-*"            # Allow public buckets for websites
        - "cdn-assets-*"                # Allow CDN asset buckets
      enforce_block_public_acls: true
      enforce_block_public_policy: true
    
    # Security Group Configuration
    aws-ec2-security-group-ingress-ssh:
      severity: "critical"
      allowed_cidrs:
        - "10.0.0.0/8"                  # Private networks
        - "172.16.0.0/12"
        - "192.168.0.0/16"
      allowed_security_groups:
        - "sg-bastion-*"                # Bastion host security groups
      exceptions:
        - "*-emergency-access"          # Emergency access groups
    
    # IAM Configuration
    aws-iam-policy-no-admin:
      severity: "high"
      allowed_principals:
        - "arn:aws:iam::123456789012:root"  # Account root
        - "arn:aws:iam::123456789012:role/AdminRole"
      exceptions:
        - "*-break-glass-*"             # Emergency break-glass policies
    
    # Azure Configuration
    azure-storage-account-https:
      severity: "medium"
      exceptions:
        - "legacy-*"                    # Legacy storage accounts
    
    # GCP Configuration
    gcp-compute-firewall-ingress-ssh:
      severity: "high"
      allowed_source_ranges:
        - "10.0.0.0/8"
      allowed_tags:
        - "ssh-allowed"
        - "bastion"
    
    # Kubernetes Configuration
    kubernetes-pod-security-context:
      severity: "medium"
      require_non_root: true
      require_read_only_fs: false
      allowed_capabilities: []

# ============================================================================
# OUTPUT CONFIGURATION
# ============================================================================
output:
  format: "json"                        # Override global format
  file: "terraform-lint-report.json"    # Output file path
  template: "templates/custom.tmpl"     # Custom template file
  
  # Format-specific settings
  json:
    pretty: true                        # Pretty-print JSON
    include_metadata: true              # Include file metadata
  
  html:
    theme: "dark"                       # Theme: light, dark, auto
    include_source: true                # Include source code snippets
    title: "Terraform Security Report" # Custom report title
  
  sarif:
    version: "2.1.0"                    # SARIF version
    schema_uri: "https://json.schemastore.org/sarif-2.1.0.json"

# ============================================================================
# CACHE CONFIGURATION
# ============================================================================
cache:
  enabled: true                         # Enable caching
  directory: ".terraform-linter-cache"  # Cache directory
  ttl: "24h"                           # Cache TTL (time to live)
  max_size: "100MB"                    # Maximum cache size
  cleanup_interval: "1h"               # Cleanup interval

# ============================================================================
# PROVIDER SETTINGS
# ============================================================================
providers:
  aws:
    regions:                            # Limit to specific regions
      - "us-east-1"
      - "us-west-2"
      - "eu-west-1"
    profiles:                           # AWS profiles to check
      - "default"
      - "production"
    assume_role:
      role_arn: "arn:aws:iam::123456789012:role/SecurityAuditRole"
      external_id: "unique-external-id"
  
  azure:
    subscription_ids:                   # Limit to specific subscriptions
      - "12345678-1234-1234-1234-123456789012"
    tenant_id: "87654321-4321-4321-4321-210987654321"
    environments:                       # Azure environments
      - "AzurePublicCloud"
  
  gcp:
    project_ids:                        # Limit to specific projects
      - "my-project-123"
      - "production-456"
    regions:
      - "us-central1"
      - "europe-west1"
    credentials_file: "/path/to/service-account.json"
  
  kubernetes:
    contexts:                           # Kubernetes contexts
      - "production"
      - "staging"
    namespaces:                         # Limit to specific namespaces
      - "default"
      - "kube-system"

# ============================================================================
# CUSTOM RULES
# ============================================================================
custom_rules:
  directory: "./custom-rules"           # Custom rules directory
  enabled: true                         # Enable custom rules
  
  # Define custom rules inline
  rules:
    - name: "company-tagging-standard"
      description: "Ensure all resources have required company tags"
      severity: "medium"
      resource_types: ["*"]
      conditions:
        - type: "attribute_exists"
          attribute: "tags.Environment"
        - type: "attribute_exists"
          attribute: "tags.Owner"
        - type: "attribute_exists"
          attribute: "tags.Project"
      message: "Resource missing required company tags (Environment, Owner, Project)"
    
    - name: "company-naming-convention"
      description: "Enforce company naming convention"
      severity: "low"
      resource_types: ["aws_s3_bucket", "aws_instance"]
      conditions:
        - type: "attribute_regex"
          attribute: "name"
          pattern: "^(dev|staging|prod)-[a-z0-9-]+-[a-z0-9]+$"
      message: "Resource name doesn't follow company naming convention"

# ============================================================================
# NOTIFICATIONS
# ============================================================================
notifications:
  enabled: true
  
  slack:
    webhook_url: "${SLACK_WEBHOOK_URL}"
    channel: "#security-alerts"
    username: "terraform-linter"
    icon_emoji: ":warning:"
    mention_users: ["@security-team"]
    severity_threshold: "high"          # Only notify for high+ severity
  
  email:
    smtp_server: "smtp.company.com"
    smtp_port: 587
    username: "${SMTP_USERNAME}"
    password: "${SMTP_PASSWORD}"
    from: "terraform-linter@company.com"
    recipients:
      - "security@company.com"
      - "devops@company.com"
    subject_template: "[SECURITY] Terraform Issues Found - {{.Summary.Total}} issues"
    severity_threshold: "medium"
  
  webhook:
    url: "https://api.company.com/security/terraform-alerts"
    method: "POST"
    headers:
      Authorization: "Bearer ${API_TOKEN}"
      Content-Type: "application/json"
    timeout: "30s"
    retry_count: 3

# ============================================================================
# INTEGRATION SETTINGS
# ============================================================================
integrations:
  github:
    token: "${GITHUB_TOKEN}"
    create_issues: true                 # Create GitHub issues for findings
    labels: ["security", "terraform"]
    assignees: ["security-team"]
  
  jira:
    url: "https://company.atlassian.net"
    username: "${JIRA_USERNAME}"
    token: "${JIRA_TOKEN}"
    project: "SEC"
    issue_type: "Security Finding"
  
  sonarqube:
    url: "https://sonar.company.com"
    token: "${SONAR_TOKEN}"
    project_key: "terraform-security"

# ============================================================================
# ADVANCED SETTINGS
# ============================================================================
advanced:
  # Parser settings
  parser:
    max_file_size: "10MB"              # Maximum file size to parse
    timeout: "30s"                     # Parser timeout per file
    ignore_unknown_values: true       # Ignore unknown/computed values
  
  # Memory settings
  memory:
    max_heap_size: "512MB"             # Maximum heap size
    gc_percentage: 100                 # Garbage collection target percentage
  
  # Logging settings
  logging:
    level: "info"                      # Log level: debug, info, warn, error
    format: "json"                     # Log format: text, json
    file: "/var/log/terraform-linter.log"
    max_size: "100MB"
    max_backups: 5
    max_age: 30                        # Days
  
  # Security settings
  security:
    disable_network_access: false     # Disable network access for rules
    sandbox_mode: false               # Run in sandbox mode
    max_execution_time: "5m"          # Maximum execution time
```

## 🎯 General Settings

### Basic Configuration
```yaml
# Minimum configuration
severity: "medium"
format: "text"
verbose: false

# File patterns
include: ["**/*.tf", "**/*.tfvars"]
exclude: ["**/test/**", "**/.terraform/**"]
```

### Performance Tuning
```yaml
# Performance optimization
parallel: 8                    # Use 8 workers
timeout: 60                    # 60 second timeout per file
cache:
  enabled: true
  ttl: "12h"                   # Cache for 12 hours
  max_size: "500MB"
```

## 🔧 Rule Configuration

### Enabling/Disabling Rules
```yaml
rules:
  # Enable specific rule patterns
  enabled:
    - "aws-s3-*"               # All AWS S3 rules
    - "security-*"             # All security rules
    - "aws-ec2-security-group-*" # Specific rule family
  
  # Disable specific rules
  disabled:
    - "aws-s3-bucket-versioning"
    - "azure-storage-https-only"
  
  # Rule priorities (override default severity)
  priorities:
    aws-iam-policy-admin-access: "critical"
    gcp-compute-firewall-ssh: "high"
```

### Rule-Specific Settings
```yaml
rules:
  settings:
    # Configure S3 bucket rules
    aws-s3-bucket-public-access-block:
      severity: "high"
      exceptions:
        - "public-website-*"
        - "*-cdn-assets"
      custom_message: "S3 bucket allows public access - this violates company policy"
    
    # Configure security group rules
    aws-ec2-security-group-ingress-ssh:
      allowed_cidrs:
        - "10.0.0.0/8"          # Corporate network
        - "192.168.1.0/24"      # VPN network
      allowed_ports: [22, 2222]  # SSH and alternative SSH
      exceptions:
        - "emergency-access-*"   # Emergency access groups
```

### Custom Rule Definitions
```yaml
custom_rules:
  rules:
    - name: "require-backup-tags"
      description: "All databases must have backup tags"
      severity: "medium"
      resource_types: 
        - "aws_db_instance"
        - "aws_rds_cluster"
      conditions:
        - type: "attribute_exists"
          attribute: "tags.BackupSchedule"
        - type: "attribute_regex"
          attribute: "tags.BackupSchedule"
          pattern: "^(daily|weekly|monthly)$"
      message: "Database resources must have a BackupSchedule tag with value: daily, weekly, or monthly"
      fix_suggestion: |
        Add the following tags to your resource:
        tags = {
          BackupSchedule = "daily"  # or weekly/monthly
        }
```

## 📊 Output Configuration

### Format-Specific Settings
```yaml
output:
  format: "html"
  file: "security-report.html"
  
  # HTML-specific settings
  html:
    theme: "dark"
    title: "Security Audit Report"
    include_source: true
    show_passed_rules: false
    group_by: "severity"        # severity, file, rule
  
  # JSON-specific settings
  json:
    pretty: true
    include_metadata: true
    include_context: true
  
  # SARIF-specific settings
  sarif:
    version: "2.1.0"
    include_snippets: true
    tool_name: "terraform-linter"
```

### Custom Templates
```yaml
output:
  template: "templates/custom-report.tmpl"
  template_data:
    company_name: "Acme Corp"
    report_date: "{{.Now.Format \"2006-01-02\"}}"
    environment: "production"
```

## 🚀 Performance Settings

### Optimization for Large Repositories
```yaml
# Large repository optimization
parallel: 16                   # More workers
timeout: 120                   # Longer timeout
cache:
  enabled: true
  ttl: "6h"                    # Shorter cache TTL
  max_size: "1GB"              # Larger cache

# Memory optimization
advanced:
  memory:
    max_heap_size: "2GB"
    gc_percentage: 50          # More aggressive GC
  
  parser:
    max_file_size: "50MB"      # Larger file limit
    timeout: "60s"
```

### CI/CD Optimization
```yaml
# Fast CI/CD scanning
parallel: 4                    # Limited workers for CI
timeout: 30                    # Quick timeout
cache:
  enabled: false               # Disable cache in CI
severity: "high"               # Only high severity issues
format: "sarif"                # SARIF for GitHub integration
```

## ☁️ Provider Settings

### AWS Configuration
```yaml
providers:
  aws:
    regions: ["us-east-1", "us-west-2"]
    profiles: ["default", "prod"]
    assume_role:
      role_arn: "arn:aws:iam::123456789012:role/SecurityRole"
      session_name: "terraform-linter"
      external_id: "unique-id"
    
    # Service-specific settings
    s3:
      check_bucket_policies: true
      check_public_access_block: true
    ec2:
      check_security_groups: true
      check_key_pairs: false
    iam:
      check_policies: true
      check_roles: true
      check_users: false
```

### Multi-Cloud Configuration
```yaml
providers:
  aws:
    regions: ["us-east-1"]
    profiles: ["aws-prod"]
  
  azure:
    subscription_ids: ["12345678-1234-1234-1234-123456789012"]
    tenant_id: "87654321-4321-4321-4321-210987654321"
  
  gcp:
    project_ids: ["my-gcp-project"]
    credentials_file: "/path/to/gcp-creds.json"
  
  kubernetes:
    contexts: ["prod-cluster"]
    config_file: "/path/to/kubeconfig"
```

## 🌍 Environment Variables

### Configuration via Environment
```bash
# File patterns
export TF_LINTER_INCLUDE="**/*.tf,**/*.tfvars"
export TF_LINTER_EXCLUDE="**/test/**"

# Basic settings
export TF_LINTER_SEVERITY="high"
export TF_LINTER_FORMAT="json"
export TF_LINTER_VERBOSE="true"
export TF_LINTER_PARALLEL="8"

# Output settings
export TF_LINTER_OUTPUT_FILE="report.json"
export TF_LINTER_OUTPUT_FORMAT="json"

# Cache settings
export TF_LINTER_CACHE_ENABLED="true"
export TF_LINTER_CACHE_DIR=".cache/terraform-linter"
export TF_LINTER_CACHE_TTL="24h"

# Provider settings
export AWS_PROFILE="production"
export AWS_REGION="us-east-1"
export AZURE_SUBSCRIPTION_ID="12345678-1234-1234-1234-123456789012"
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/gcp-creds.json"

# Integration settings
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
export GITHUB_TOKEN="ghp_xxxxxxxxxxxxxxxxxxxx"
export JIRA_TOKEN="xxxxxxxxxxxxxxxxxxxx"
```

### Environment Variable Priority
1. Command line flags (highest priority)
2. Environment variables
3. Configuration file
4. Default values (lowest priority)

## 📚 Examples

### Example 1: Development Environment
```yaml
# .terraform-linter-dev.yml
severity: "medium"
format: "text"
verbose: true
parallel: 2

include: ["**/*.tf"]
exclude: 
  - "**/test/**"
  - "**/examples/**"

rules:
  disabled:
    - "aws-s3-bucket-versioning"     # Not needed in dev
    - "aws-ec2-detailed-monitoring"  # Cost optimization
```

### Example 2: Production Environment
```yaml
# .terraform-linter-prod.yml
severity: "low"                       # Catch everything
format: "sarif"
output:
  file: "prod-security-scan.sarif"

rules:
  enabled: ["*"]                      # All rules
  settings:
    aws-s3-bucket-public-access-block:
      severity: "critical"            # Stricter in prod
    aws-iam-policy-admin-access:
      severity: "critical"

notifications:
  slack:
    webhook_url: "${SLACK_WEBHOOK_URL}"
    channel: "#security-prod"
    severity_threshold: "high"
```

### Example 3: CI/CD Pipeline
```yaml
# .terraform-linter-ci.yml
severity: "high"                      # Only important issues
format: "sarif"
quiet: true                           # Minimal output
parallel: 4                           # Limited resources
timeout: 60                           # Quick scan

cache:
  enabled: false                      # No cache in CI

output:
  file: "results.sarif"

exclude:
  - "**/test/**"
  - "**/examples/**"
  - "**/.terraform/**"
```

### Example 4: Security Audit
```yaml
# .terraform-linter-audit.yml
severity: "low"                       # Comprehensive scan
format: "html"
verbose: true

output:
  file: "security-audit-report.html"
  html:
    theme: "light"
    title: "Terraform Security Audit"
    include_source: true

rules:
  enabled: ["security-*", "aws-iam-*", "azure-security-*"]
  
notifications:
  email:
    recipients: ["security@company.com", "compliance@company.com"]
    subject_template: "Security Audit Complete - {{.Summary.Total}} findings"
```

### Example 5: Multi-Environment
```yaml
# .terraform-linter.yml
version: "1.0"

# Base configuration
severity: "medium"
format: "json"

# Environment-specific overrides
environments:
  development:
    severity: "high"
    rules:
      disabled: ["aws-s3-bucket-versioning", "cost-optimization-*"]
  
  staging:
    severity: "medium"
    notifications:
      slack:
        channel: "#staging-alerts"
  
  production:
    severity: "low"
    rules:
      settings:
        aws-s3-bucket-public-access-block:
          severity: "critical"
    notifications:
      slack:
        channel: "#production-alerts"
        severity_threshold: "high"
      email:
        recipients: ["security@company.com"]
```

## 🔍 Configuration Validation

### Validate Configuration
```bash
# Validate configuration file
terraform-linter --config .terraform-linter.yml --validate-config

# Show effective configuration
terraform-linter --config .terraform-linter.yml --show-config

# Test configuration with dry run
terraform-linter --config .terraform-linter.yml --dry-run .
```

### Configuration Schema
The linter supports JSON Schema validation for configuration files:

```bash
# Generate schema
terraform-linter --generate-schema > terraform-linter-schema.json

# Validate against schema
terraform-linter --validate-schema .terraform-linter.yml
```

---

**Next Steps**: 
- Explore [Available Rules](RULES.md)
- Check [Usage Examples](USAGE.md)
- See [Development Guide](DEVELOPMENT.md) 