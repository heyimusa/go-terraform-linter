# 📋 Rules Documentation

This guide covers all available rules in the Go Terraform Linter, organized by cloud provider and category.

## 📋 Table of Contents

- [Overview](#overview)
- [Rule Categories](#rule-categories)
- [AWS Rules](#aws-rules)
- [Azure Rules](#azure-rules)
- [GCP Rules](#gcp-rules)
- [Kubernetes Rules](#kubernetes-rules)
- [Generic Rules](#generic-rules)
- [Custom Rules](#custom-rules)
- [Rule Configuration](#rule-configuration)

## 🔍 Overview

### Rule Naming Convention
Rules follow a consistent naming pattern:
```
{provider}-{service}-{resource}-{check}
```

Examples:
- `aws-s3-bucket-public-access-block`
- `azure-storage-account-https-only`
- `gcp-compute-firewall-ingress-ssh`
- `kubernetes-pod-security-context`

### Severity Levels
- **🔴 Critical**: Immediate security risk, production impact
- **🟠 High**: Significant security concern, should be fixed soon
- **🟡 Medium**: Security best practice, recommended fix
- **🟢 Low**: Minor improvement, nice to have

### Rule Status
- ✅ **Enabled**: Rule is active by default
- ⚠️ **Configurable**: Rule behavior can be customized
- 🔧 **Auto-fix**: Rule provides automatic fix suggestions
- 📚 **Documentation**: Links to official documentation

## 📂 Rule Categories

### Security Rules
Focus on security vulnerabilities and misconfigurations:
- Access controls and permissions
- Encryption and data protection
- Network security
- Authentication and authorization

### Compliance Rules
Ensure compliance with standards and regulations:
- CIS Benchmarks
- PCI DSS
- SOC 2
- GDPR

### Best Practices Rules
Enforce operational best practices:
- Resource tagging
- Naming conventions
- Cost optimization
- Performance optimization

### Reliability Rules
Improve system reliability and availability:
- Backup and recovery
- Monitoring and alerting
- High availability
- Disaster recovery

## ☁️ AWS Rules

### S3 (Simple Storage Service)

#### aws-s3-bucket-public-access-block
- **Severity**: 🔴 Critical
- **Category**: Security
- **Status**: ✅ Enabled, ⚠️ Configurable, 🔧 Auto-fix
- **Description**: Ensures S3 buckets have public access block configuration
- **Risk**: Public S3 buckets can lead to data breaches and unauthorized access

```hcl
# ❌ Bad - No public access block
resource "aws_s3_bucket" "bad" {
  bucket = "my-bucket"
}

# ✅ Good - Public access blocked
resource "aws_s3_bucket" "good" {
  bucket = "my-bucket"
}

resource "aws_s3_bucket_public_access_block" "good" {
  bucket = aws_s3_bucket.good.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

**Configuration**:
```yaml
rules:
  settings:
    aws-s3-bucket-public-access-block:
      severity: "critical"
      exceptions: ["public-website-*", "cdn-assets-*"]
      enforce_all_settings: true
```

#### aws-s3-bucket-encryption
- **Severity**: 🟠 High
- **Category**: Security
- **Status**: ✅ Enabled, 🔧 Auto-fix
- **Description**: Ensures S3 buckets have encryption enabled
- **Risk**: Unencrypted data at rest

```hcl
# ❌ Bad - No encryption
resource "aws_s3_bucket" "bad" {
  bucket = "my-bucket"
}

# ✅ Good - AES256 encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "good" {
  bucket = aws_s3_bucket.good.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
```

#### aws-s3-bucket-versioning
- **Severity**: 🟡 Medium
- **Category**: Best Practices
- **Status**: ✅ Enabled, ⚠️ Configurable
- **Description**: Ensures S3 buckets have versioning enabled
- **Risk**: Data loss without versioning

#### aws-s3-bucket-logging
- **Severity**: 🟡 Medium
- **Category**: Compliance
- **Status**: ✅ Enabled
- **Description**: Ensures S3 buckets have access logging enabled
- **Risk**: No audit trail for access

### EC2 (Elastic Compute Cloud)

#### aws-ec2-security-group-ingress-ssh
- **Severity**: 🔴 Critical
- **Category**: Security
- **Status**: ✅ Enabled, ⚠️ Configurable
- **Description**: Prevents SSH access from 0.0.0.0/0
- **Risk**: Unrestricted SSH access enables brute force attacks

```hcl
# ❌ Bad - SSH from anywhere
resource "aws_security_group" "bad" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ✅ Good - SSH from specific CIDR
resource "aws_security_group" "good" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
```

**Configuration**:
```yaml
rules:
  settings:
    aws-ec2-security-group-ingress-ssh:
      allowed_cidrs:
        - "10.0.0.0/8"
        - "192.168.0.0/16"
      allowed_security_groups:
        - "sg-bastion-*"
      exceptions:
        - "*-emergency-access"
```

#### aws-ec2-security-group-ingress-rdp
- **Severity**: 🔴 Critical
- **Category**: Security
- **Status**: ✅ Enabled, ⚠️ Configurable
- **Description**: Prevents RDP access from 0.0.0.0/0
- **Risk**: Unrestricted RDP access

#### aws-ec2-instance-iam-role
- **Severity**: 🟠 High
- **Category**: Security
- **Status**: ✅ Enabled
- **Description**: Ensures EC2 instances use IAM roles instead of access keys
- **Risk**: Hardcoded credentials

#### aws-ec2-instance-detailed-monitoring
- **Severity**: 🟢 Low
- **Category**: Best Practices
- **Status**: ⚠️ Configurable
- **Description**: Recommends detailed monitoring for production instances
- **Risk**: Limited observability

### IAM (Identity and Access Management)

#### aws-iam-policy-no-admin-access
- **Severity**: 🔴 Critical
- **Category**: Security
- **Status**: ✅ Enabled, ⚠️ Configurable
- **Description**: Prevents policies with full admin access (*)
- **Risk**: Excessive permissions, privilege escalation

```hcl
# ❌ Bad - Admin access
resource "aws_iam_policy" "bad" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# ✅ Good - Specific permissions
resource "aws_iam_policy" "good" {
  policy = jsonencode({
    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:GetObject",
        "s3:PutObject"
      ]
      Resource = "arn:aws:s3:::my-bucket/*"
    }]
  })
}
```

#### aws-iam-user-no-access-keys
- **Severity**: 🟠 High
- **Category**: Security
- **Status**: ✅ Enabled
- **Description**: Discourages IAM user access keys in favor of roles
- **Risk**: Long-lived credentials

#### aws-iam-password-policy
- **Severity**: 🟡 Medium
- **Category**: Security
- **Status**: ✅ Enabled, ⚠️ Configurable
- **Description**: Ensures strong password policy
- **Risk**: Weak passwords

### RDS (Relational Database Service)

#### aws-rds-instance-encryption
- **Severity**: 🟠 High
- **Category**: Security
- **Status**: ✅ Enabled
- **Description**: Ensures RDS instances have encryption enabled
- **Risk**: Unencrypted database

#### aws-rds-instance-backup
- **Severity**: 🟡 Medium
- **Category**: Reliability
- **Status**: ✅ Enabled, ⚠️ Configurable
- **Description**: Ensures RDS instances have automated backups
- **Risk**: Data loss

#### aws-rds-instance-multi-az
- **Severity**: 🟡 Medium
- **Category**: Reliability
- **Status**: ⚠️ Configurable
- **Description**: Recommends Multi-AZ for production databases
- **Risk**: Single point of failure

### Lambda

#### aws-lambda-function-dead-letter-queue
- **Severity**: 🟡 Medium
- **Category**: Reliability
- **Status**: ✅ Enabled
- **Description**: Ensures Lambda functions have dead letter queues
- **Risk**: Lost events on failure

#### aws-lambda-function-tracing
- **Severity**: 🟢 Low
- **Category**: Best Practices
- **Status**: ⚠️ Configurable
- **Description**: Recommends X-Ray tracing for Lambda functions
- **Risk**: Limited observability

## 🔷 Azure Rules

### Storage Account

#### azure-storage-account-https-only
- **Severity**: 🟠 High
- **Category**: Security
- **Status**: ✅ Enabled
- **Description**: Ensures storage accounts require HTTPS
- **Risk**: Data in transit not encrypted

```hcl
# ❌ Bad - HTTP allowed
resource "azurerm_storage_account" "bad" {
  name                     = "mystorageaccount"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

# ✅ Good - HTTPS required
resource "azurerm_storage_account" "good" {
  name                     = "mystorageaccount"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  enable_https_traffic_only = true
}
```

#### azure-storage-account-encryption
- **Severity**: 🟠 High
- **Category**: Security
- **Status**: ✅ Enabled
- **Description**: Ensures storage accounts have encryption enabled
- **Risk**: Unencrypted data at rest

### Virtual Machine

#### azure-vm-disk-encryption
- **Severity**: 🟠 High
- **Category**: Security
- **Status**: ✅ Enabled
- **Description**: Ensures VM disks are encrypted
- **Risk**: Unencrypted VM storage

#### azure-vm-network-security-group
- **Severity**: 🟡 Medium
- **Category**: Security
- **Status**: ✅ Enabled
- **Description**: Ensures VMs have network security groups
- **Risk**: Unrestricted network access

### Network Security Group

#### azure-nsg-rule-ssh-unrestricted
- **Severity**: 🔴 Critical
- **Category**: Security
- **Status**: ✅ Enabled, ⚠️ Configurable
- **Description**: Prevents SSH access from 0.0.0.0/0
- **Risk**: Unrestricted SSH access

#### azure-nsg-rule-rdp-unrestricted
- **Severity**: 🔴 Critical
- **Category**: Security
- **Status**: ✅ Enabled, ⚠️ Configurable
- **Description**: Prevents RDP access from 0.0.0.0/0
- **Risk**: Unrestricted RDP access

### Key Vault

#### azure-key-vault-soft-delete
- **Severity**: 🟡 Medium
- **Category**: Reliability
- **Status**: ✅ Enabled
- **Description**: Ensures Key Vault has soft delete enabled
- **Risk**: Permanent key deletion

#### azure-key-vault-purge-protection
- **Severity**: 🟡 Medium
- **Category**: Security
- **Status**: ✅ Enabled
- **Description**: Ensures Key Vault has purge protection
- **Risk**: Accidental key deletion

## 🟢 GCP Rules

### Compute Engine

#### gcp-compute-firewall-ingress-ssh
- **Severity**: 🔴 Critical
- **Category**: Security
- **Status**: ✅ Enabled, ⚠️ Configurable
- **Description**: Prevents SSH access from 0.0.0.0/0
- **Risk**: Unrestricted SSH access

```hcl
# ❌ Bad - SSH from anywhere
resource "google_compute_firewall" "bad" {
  name    = "allow-ssh"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["0.0.0.0/0"]
}

# ✅ Good - SSH from specific ranges
resource "google_compute_firewall" "good" {
  name    = "allow-ssh"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["10.0.0.0/8"]
  target_tags   = ["ssh-allowed"]
}
```

#### gcp-compute-disk-encryption
- **Severity**: 🟠 High
- **Category**: Security
- **Status**: ✅ Enabled
- **Description**: Ensures compute disks are encrypted
- **Risk**: Unencrypted disk storage

#### gcp-compute-instance-service-account
- **Severity**: 🟡 Medium
- **Category**: Security
- **Status**: ✅ Enabled
- **Description**: Ensures instances don't use default service account
- **Risk**: Excessive permissions

### Cloud Storage

#### gcp-storage-bucket-public-access
- **Severity**: 🔴 Critical
- **Category**: Security
- **Status**: ✅ Enabled, ⚠️ Configurable
- **Description**: Prevents public access to storage buckets
- **Risk**: Data exposure

#### gcp-storage-bucket-uniform-access
- **Severity**: 🟡 Medium
- **Category**: Security
- **Status**: ✅ Enabled
- **Description**: Recommends uniform bucket-level access
- **Risk**: Complex ACL management

### Cloud SQL

#### gcp-sql-instance-ssl
- **Severity**: 🟠 High
- **Category**: Security
- **Status**: ✅ Enabled
- **Description**: Ensures Cloud SQL requires SSL
- **Risk**: Unencrypted database connections

#### gcp-sql-instance-backup
- **Severity**: 🟡 Medium
- **Category**: Reliability
- **Status**: ✅ Enabled
- **Description**: Ensures Cloud SQL has automated backups
- **Risk**: Data loss

## ☸️ Kubernetes Rules

### Pod Security

#### kubernetes-pod-security-context
- **Severity**: 🟡 Medium
- **Category**: Security
- **Status**: ✅ Enabled, ⚠️ Configurable
- **Description**: Ensures pods have security context configured
- **Risk**: Containers running as root

```yaml
# ❌ Bad - No security context
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: app
    image: nginx

# ✅ Good - Security context configured
apiVersion: v1
kind: Pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 2000
  containers:
  - name: app
    image: nginx
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
```

#### kubernetes-pod-resource-limits
- **Severity**: 🟡 Medium
- **Category**: Best Practices
- **Status**: ✅ Enabled, ⚠️ Configurable
- **Description**: Ensures pods have resource limits
- **Risk**: Resource exhaustion

#### kubernetes-pod-image-pull-policy
- **Severity**: 🟢 Low
- **Category**: Best Practices
- **Status**: ✅ Enabled
- **Description**: Ensures proper image pull policy
- **Risk**: Stale container images

### Network Policies

#### kubernetes-network-policy-default-deny
- **Severity**: 🟡 Medium
- **Category**: Security
- **Status**: ⚠️ Configurable
- **Description**: Recommends default deny network policies
- **Risk**: Unrestricted pod communication

### Service Account

#### kubernetes-service-account-token-mount
- **Severity**: 🟡 Medium
- **Category**: Security
- **Status**: ✅ Enabled
- **Description**: Prevents automatic service account token mounting
- **Risk**: Unnecessary API access

### RBAC

#### kubernetes-rbac-wildcard-permissions
- **Severity**: 🟠 High
- **Category**: Security
- **Status**: ✅ Enabled
- **Description**: Prevents wildcard permissions in RBAC
- **Risk**: Excessive permissions

## 🔧 Generic Rules

### Tagging and Naming

#### resource-required-tags
- **Severity**: 🟡 Medium
- **Category**: Best Practices
- **Status**: ⚠️ Configurable
- **Description**: Ensures resources have required tags
- **Risk**: Poor resource management

```yaml
# Configuration
rules:
  settings:
    resource-required-tags:
      required_tags:
        - "Environment"
        - "Owner"
        - "Project"
        - "CostCenter"
      exceptions:
        - "aws_s3_bucket_policy"  # Doesn't support tags
```

#### resource-naming-convention
- **Severity**: 🟢 Low
- **Category**: Best Practices
- **Status**: ⚠️ Configurable
- **Description**: Enforces naming conventions
- **Risk**: Inconsistent naming

### Security

#### hardcoded-secrets
- **Severity**: 🔴 Critical
- **Category**: Security
- **Status**: ✅ Enabled
- **Description**: Detects hardcoded secrets and passwords
- **Risk**: Credential exposure

#### insecure-protocols
- **Severity**: 🟠 High
- **Category**: Security
- **Status**: ✅ Enabled
- **Description**: Detects usage of insecure protocols (HTTP, FTP, etc.)
- **Risk**: Data interception

### Compliance

#### cis-benchmark
- **Severity**: Various
- **Category**: Compliance
- **Status**: ⚠️ Configurable
- **Description**: CIS Benchmark compliance checks
- **Risk**: Regulatory non-compliance

## 🎨 Custom Rules

### Creating Custom Rules

You can create custom rules using YAML configuration:

```yaml
custom_rules:
  rules:
    - name: "company-backup-policy"
      description: "All databases must have backup configuration"
      severity: "high"
      resource_types:
        - "aws_db_instance"
        - "aws_rds_cluster"
        - "azurerm_sql_database"
        - "google_sql_database_instance"
      conditions:
        - type: "attribute_exists"
          attribute: "backup_retention_period"
        - type: "attribute_greater_than"
          attribute: "backup_retention_period"
          value: 7
      message: "Database must have backup retention period > 7 days"
      fix_suggestion: |
        Add backup configuration:
        backup_retention_period = 30
        backup_window          = "03:00-04:00"
    
    - name: "company-encryption-standard"
      description: "All storage must use company-approved encryption"
      severity: "critical"
      resource_types: ["*"]
      conditions:
        - type: "attribute_regex"
          attribute: "kms_key_id"
          pattern: "^arn:aws:kms:.*:123456789012:key/.*"
      message: "Must use company KMS keys for encryption"
```

### Custom Rule Types

#### Condition Types
- `attribute_exists`: Check if attribute exists
- `attribute_equals`: Check if attribute equals value
- `attribute_regex`: Check if attribute matches regex
- `attribute_greater_than`: Numeric comparison
- `attribute_less_than`: Numeric comparison
- `attribute_contains`: Check if attribute contains value
- `block_exists`: Check if block exists
- `resource_count`: Check resource count

#### Advanced Custom Rules
```yaml
custom_rules:
  rules:
    - name: "multi-condition-example"
      description: "Complex rule with multiple conditions"
      severity: "medium"
      resource_types: ["aws_instance"]
      conditions:
        - type: "attribute_exists"
          attribute: "tags"
        - type: "attribute_exists"
          attribute: "tags.Environment"
        - type: "attribute_regex"
          attribute: "tags.Environment"
          pattern: "^(dev|staging|prod)$"
        - type: "block_exists"
          block: "monitoring"
      logic: "AND"  # ALL conditions must match
      message: "EC2 instances must have proper tags and monitoring"
```

## ⚙️ Rule Configuration

### Global Rule Settings
```yaml
rules:
  # Enable/disable rules
  enabled: ["aws-*", "security-*"]
  disabled: ["aws-s3-bucket-versioning"]
  
  # Global severity overrides
  severity_overrides:
    aws-s3-bucket-public-access-block: "critical"
    aws-ec2-security-group-ingress-ssh: "critical"
  
  # Rule-specific settings
  settings:
    aws-s3-bucket-public-access-block:
      exceptions: ["public-website-*"]
      enforce_all_settings: true
    
    resource-required-tags:
      required_tags: ["Environment", "Owner"]
      tag_format:
        Environment: "^(dev|staging|prod)$"
        Owner: "^[a-z]+\\.[a-z]+@company\\.com$"
```

### Environment-Specific Rules
```yaml
environments:
  development:
    rules:
      disabled: 
        - "aws-s3-bucket-versioning"
        - "cost-optimization-*"
      severity_overrides:
        aws-ec2-instance-detailed-monitoring: "low"
  
  production:
    rules:
      enabled: ["*"]
      severity_overrides:
        aws-s3-bucket-public-access-block: "critical"
        aws-iam-policy-no-admin-access: "critical"
```

### Rule Profiles
```yaml
profiles:
  security-focused:
    rules:
      enabled: ["security-*", "aws-iam-*", "encryption-*"]
      severity_overrides:
        "*": "high"  # Elevate all security rules
  
  cost-optimized:
    rules:
      enabled: ["cost-*", "aws-ec2-instance-*"]
      disabled: ["aws-s3-bucket-versioning"]  # Save on storage costs
  
  compliance-pci:
    rules:
      enabled: ["pci-*", "encryption-*", "access-control-*"]
      settings:
        encryption-requirements:
          min_key_length: 256
          approved_algorithms: ["AES-256", "RSA-2048"]
```

## 📊 Rule Statistics

### Coverage by Provider
- **AWS**: 45+ rules across 12 services
- **Azure**: 25+ rules across 8 services  
- **GCP**: 20+ rules across 6 services
- **Kubernetes**: 15+ rules across 5 categories
- **Generic**: 10+ rules for common patterns

### Coverage by Category
- **Security**: 60+ rules (65%)
- **Best Practices**: 20+ rules (22%)
- **Compliance**: 8+ rules (9%)
- **Reliability**: 4+ rules (4%)

### Severity Distribution
- **🔴 Critical**: 15 rules (16%)
- **🟠 High**: 25 rules (27%)
- **🟡 Medium**: 35 rules (38%)
- **🟢 Low**: 17 rules (19%)

---

**Next Steps**:
- Review [Configuration Guide](CONFIGURATION.md) for rule customization
- Check [Usage Examples](USAGE.md) for practical implementations
- See [Development Guide](DEVELOPMENT.md) for creating custom rules 