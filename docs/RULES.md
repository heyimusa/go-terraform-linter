# 📋 Rules Documentation

This guide covers all **100+ security rules** in the Go Terraform Linter, organized by cloud provider and category.

## 📋 Table of Contents

- [Overview](#overview)
- [Rule Categories](#rule-categories)
- [AWS Rules (30+)](#aws-rules)
- [Azure Rules (25+)](#azure-rules)
- [GCP Rules (25+)](#gcp-rules)
- [Kubernetes Rules (20+)](#kubernetes-rules)
- [Generic Rules (15+)](#generic-rules)
- [Custom Rules](#custom-rules)
- [Rule Configuration](#rule-configuration)

## 🔍 Overview

### Rule Naming Convention
Rules follow a consistent naming pattern:
```
{provider}-{service}-{resource}-{check}
```

Examples:
- `aws-s3-bucket-public-read`
- `azure-storage-account-https-only`
- `gcp-compute-instance-public-ip`
- `k8s-pod-security-context`

### Severity Levels
- **🚨 Critical**: Immediate security risk, production impact (score: 9.0-10.0)
- **⚠️ High**: Significant security concern, should be fixed soon (score: 7.0-8.9)
- **⚡ Medium**: Security best practice, recommended fix (score: 4.0-6.9)
- **ℹ️ Low**: Minor improvement, nice to have (score: 1.0-3.9)

### Rule Metadata
Each rule includes comprehensive metadata:
- **Provider**: AWS, Azure, GCP, Kubernetes, Generic
- **Category**: Security, Compliance, Best Practices, Performance
- **Tags**: Descriptive tags for filtering and organization
- **Version**: Rule version for compatibility tracking
- **CWE**: Common Weakness Enumeration mapping
- **Compliance**: SOC2, HIPAA, PCI-DSS, CIS benchmark mappings

### Rule Status
- ✅ **Production Ready**: Thoroughly tested and validated
- 🔧 **Auto-fix**: Provides automatic fix suggestions
- 📚 **Documentation**: Links to official documentation and best practices

## 📂 Rule Categories

### Security Rules (70+ rules)
Focus on security vulnerabilities and misconfigurations:
- **Access Controls**: Public access, IAM permissions, RBAC
- **Encryption**: Data at rest, data in transit, key management
- **Network Security**: Firewall rules, VPC configuration, ingress/egress
- **Authentication**: Secrets management, credential exposure

### Compliance Rules (20+ rules)
Ensure compliance with standards and regulations:
- **CIS Benchmarks**: AWS, Azure, GCP, Kubernetes
- **PCI DSS**: Payment card industry standards
- **SOC 2**: System and organization controls
- **HIPAA**: Healthcare data protection

### Best Practices Rules (15+ rules)
Enforce operational best practices:
- **Resource Management**: Tagging, naming conventions, lifecycle
- **Cost Optimization**: Resource sizing, unused resources
- **Performance**: Caching, CDN usage, database optimization
- **Reliability**: Backup configuration, monitoring setup

## ☁️ AWS Rules (30+ Comprehensive Security Rules)

### 🪣 S3 Security Rules

#### aws-s3-bucket-public-read
- **Severity**: 🚨 Critical
- **Category**: Security
- **Tags**: [`s3`, `public-access`, `data-exposure`]
- **CWE**: CWE-200 (Information Exposure)
- **Compliance**: SOC2, PCI-DSS, HIPAA
- **Description**: Detects S3 buckets with public read access
- **Risk**: Public S3 buckets can lead to data breaches and unauthorized access

```hcl
# ❌ Bad - Public read access
resource "aws_s3_bucket_acl" "bad" {
  bucket = aws_s3_bucket.example.id
  acl    = "public-read"
}

# ✅ Good - Private access
resource "aws_s3_bucket_acl" "good" {
  bucket = aws_s3_bucket.example.id
  acl    = "private"
}
```

#### aws-s3-bucket-ssl-only
- **Severity**: ⚠️ High
- **Category**: Security
- **Tags**: [`s3`, `encryption`, `ssl`]
- **Description**: Ensures S3 buckets enforce SSL-only access
- **Fix**: Add bucket policy with aws:SecureTransport condition

#### aws-s3-bucket-lifecycle
- **Severity**: ℹ️ Low
- **Category**: Best Practices
- **Tags**: [`s3`, `lifecycle`, `cost-optimization`]
- **Description**: Ensures S3 buckets have lifecycle policies configured
- **Fix**: Add aws_s3_bucket_lifecycle_configuration resource

#### aws-s3-bucket-mfa-delete
- **Severity**: ⚡ Medium
- **Category**: Security
- **Tags**: [`s3`, `mfa`, `deletion-protection`]
- **Description**: Ensures S3 bucket versioning has MFA delete enabled
- **Fix**: Enable MFA delete in versioning configuration

### 🖥️ EC2 Security Rules

#### aws-ec2-instance-public-ip
- **Severity**: ⚡ Medium
- **Category**: Security
- **Tags**: [`ec2`, `public-ip`, `network`]
- **Description**: Detects EC2 instances with public IP addresses
- **Fix**: Set associate_public_ip_address = false

#### aws-ec2-instance-metadata-v2
- **Severity**: ⚠️ High
- **Category**: Security
- **Tags**: [`ec2`, `metadata`, `imdsv2`]
- **Description**: Ensures EC2 instances enforce IMDSv2
- **Fix**: Add metadata_options block with http_tokens = "required"

#### aws-ec2-instance-user-data-secrets
- **Severity**: 🚨 Critical
- **Category**: Security
- **Tags**: [`ec2`, `secrets`, `user-data`]
- **Description**: Detects potential secrets in EC2 user data
- **Fix**: Use AWS Systems Manager Parameter Store or Secrets Manager

### 🔒 Security Group Rules

#### aws-security-group-ssh-world
- **Severity**: 🚨 Critical
- **Category**: Security
- **Tags**: [`security-group`, `ssh`, `public-access`]
- **Description**: Detects security groups allowing SSH from 0.0.0.0/0
- **Fix**: Restrict source_cidr_blocks to specific IP ranges

#### aws-security-group-rdp-world
- **Severity**: 🚨 Critical
- **Category**: Security
- **Tags**: [`security-group`, `rdp`, `public-access`]
- **Description**: Detects security groups allowing RDP from 0.0.0.0/0
- **Fix**: Restrict source_cidr_blocks to specific IP ranges

### 🗄️ RDS Security Rules

#### aws-rds-instance-public
- **Severity**: ⚠️ High
- **Category**: Security
- **Tags**: [`rds`, `public-access`, `database`]
- **Description**: Detects RDS instances with public accessibility
- **Fix**: Set publicly_accessible = false

#### aws-rds-deletion-protection
- **Severity**: ⚡ Medium
- **Category**: Reliability
- **Tags**: [`rds`, `deletion-protection`, `data-protection`]
- **Description**: Ensures RDS instances have deletion protection enabled
- **Fix**: Set deletion_protection = true

### ⚡ Lambda Security Rules

#### aws-lambda-environment-secrets
- **Severity**: 🚨 Critical
- **Category**: Security
- **Tags**: [`lambda`, `secrets`, `environment-variables`]
- **Description**: Detects potential secrets in Lambda environment variables
- **Fix**: Use AWS Systems Manager Parameter Store or Secrets Manager

#### aws-lambda-reserved-concurrency
- **Severity**: ℹ️ Low
- **Category**: Performance
- **Tags**: [`lambda`, `concurrency`, `resource-limits`]
- **Description**: Recommends reserved concurrency to prevent resource exhaustion
- **Fix**: Add reserved_concurrent_executions = <appropriate_value>

## 🔷 Azure Rules (25+ Comprehensive Security Rules)

### 💾 Storage Account Security Rules

#### azure-storage-account-https-only
- **Severity**: ⚠️ High
- **Category**: Security
- **Tags**: [`storage`, `https`, `encryption`]
- **Description**: Ensures storage accounts enforce HTTPS-only access
- **Fix**: Set https_traffic_only_enabled = true

#### azure-storage-account-public-access
- **Severity**: 🚨 Critical
- **Category**: Security
- **Tags**: [`storage`, `public-access`, `data-exposure`]
- **Description**: Detects storage accounts with public access enabled
- **Fix**: Set public_network_access_enabled = false

#### azure-storage-account-min-tls
- **Severity**: ⚡ Medium
- **Category**: Security
- **Tags**: [`storage`, `tls`, `encryption`]
- **Description**: Ensures storage accounts enforce minimum TLS version 1.2
- **Fix**: Set min_tls_version = "TLS1_2"

### 🖥️ Virtual Machine Security Rules

#### azure-vm-public-ip
- **Severity**: ⚡ Medium
- **Category**: Security
- **Tags**: [`vm`, `public-ip`, `network`]
- **Description**: Detects VMs with public IP addresses
- **Fix**: Remove public IP and use NAT Gateway or VPN

#### azure-vm-disk-encryption
- **Severity**: ⚠️ High
- **Category**: Security
- **Tags**: [`vm`, `disk`, `encryption`]
- **Description**: Ensures VM disks are encrypted
- **Fix**: Enable Azure Disk Encryption

### 🔐 Key Vault Security Rules

#### azure-key-vault-soft-delete
- **Severity**: ⚡ Medium
- **Category**: Security
- **Tags**: [`key-vault`, `soft-delete`, `data-protection`]
- **Description**: Ensures Key Vault has soft delete enabled
- **Fix**: Set soft_delete_retention_days = 90

#### azure-key-vault-purge-protection
- **Severity**: ⚠️ High
- **Category**: Security
- **Tags**: [`key-vault`, `purge-protection`, `data-protection`]
- **Description**: Ensures Key Vault has purge protection enabled
- **Fix**: Set purge_protection_enabled = true

### 🛡️ Network Security Group Rules

#### azure-nsg-ssh-world
- **Severity**: 🚨 Critical
- **Category**: Security
- **Tags**: [`nsg`, `ssh`, `public-access`]
- **Description**: Detects NSG rules allowing SSH from anywhere
- **Fix**: Restrict source_address_prefix to specific IP ranges

#### azure-nsg-rdp-world
- **Severity**: 🚨 Critical
- **Category**: Security
- **Tags**: [`nsg`, `rdp`, `public-access`]
- **Description**: Detects NSG rules allowing RDP from anywhere
- **Fix**: Restrict source_address_prefix to specific IP ranges

## 🌐 GCP Rules (25+ Comprehensive Security Rules)

### 🖥️ Compute Engine Security Rules

#### gcp-compute-instance-public-ip
- **Severity**: ⚡ Medium
- **Category**: Security
- **Tags**: [`compute`, `public-ip`, `network`]
- **Description**: Detects Compute instances with public IP addresses
- **Fix**: Remove access_config block and use Cloud NAT for outbound traffic

#### gcp-compute-instance-os-login
- **Severity**: ⚡ Medium
- **Category**: Security
- **Tags**: [`compute`, `os-login`, `authentication`]
- **Description**: Ensures Compute instances have OS Login enabled
- **Fix**: Add metadata = { "enable-oslogin" = "TRUE" }

#### gcp-compute-instance-shielded-vm
- **Severity**: ⚡ Medium
- **Category**: Security
- **Tags**: [`compute`, `shielded-vm`, `security`]
- **Description**: Ensures Compute instances have Shielded VM enabled
- **Fix**: Add shielded_instance_config block with enable_secure_boot = true

### 💾 Cloud Storage Security Rules

#### gcp-storage-bucket-public-access
- **Severity**: 🚨 Critical
- **Category**: Security
- **Tags**: [`storage`, `public-access`, `data-exposure`]
- **Description**: Detects storage buckets with public access via IAM
- **Fix**: Remove allUsers and allAuthenticatedUsers from members list

#### gcp-storage-bucket-uniform-access
- **Severity**: ⚡ Medium
- **Category**: Security
- **Tags**: [`storage`, `uniform-access`, `security`]
- **Description**: Ensures storage buckets have uniform bucket-level access enabled
- **Fix**: Add uniform_bucket_level_access block with enabled = true

#### gcp-storage-bucket-versioning
- **Severity**: ℹ️ Low
- **Category**: Data Protection
- **Tags**: [`storage`, `versioning`, `data-protection`]
- **Description**: Ensures storage buckets have versioning enabled
- **Fix**: Add versioning block with enabled = true

### 🗄️ Cloud SQL Security Rules

#### gcp-cloudsql-ssl-required
- **Severity**: ⚠️ High
- **Category**: Security
- **Tags**: [`cloudsql`, `ssl`, `encryption`]
- **Description**: Ensures Cloud SQL instances require SSL connections
- **Fix**: Add require_ssl = true in ip_configuration

#### gcp-cloudsql-backup-enabled
- **Severity**: ⚡ Medium
- **Category**: Data Protection
- **Tags**: [`cloudsql`, `backup`, `data-protection`]
- **Description**: Ensures Cloud SQL instances have automated backups enabled
- **Fix**: Add backup_configuration block with enabled = true

### 🔥 Firewall Security Rules

#### gcp-firewall-ssh-world
- **Severity**: 🚨 Critical
- **Category**: Security
- **Tags**: [`firewall`, `ssh`, `public-access`]
- **Description**: Detects firewall rules allowing SSH from anywhere
- **Fix**: Restrict source_ranges to specific IP ranges

#### gcp-firewall-rdp-world
- **Severity**: 🚨 Critical
- **Category**: Security
- **Tags**: [`firewall`, `rdp`, `public-access`]
- **Description**: Detects firewall rules allowing RDP from anywhere
- **Fix**: Restrict source_ranges to specific IP ranges

## ⚓ Kubernetes Rules (20+ Comprehensive Security Rules)

### 🚀 Pod Security Rules

#### k8s-pod-security-context
- **Severity**: ⚡ Medium
- **Category**: Security
- **Tags**: [`pod`, `security-context`, `container-security`]
- **Description**: Ensures pods have security context configured
- **Fix**: Add security_context block with appropriate security settings

#### k8s-pod-read-only-root-filesystem
- **Severity**: ⚡ Medium
- **Category**: Security
- **Tags**: [`pod`, `filesystem`, `container-security`]
- **Description**: Ensures containers have read-only root filesystem
- **Fix**: Set read_only_root_filesystem = true

#### k8s-pod-resource-limits
- **Severity**: ⚡ Medium
- **Category**: Performance
- **Tags**: [`pod`, `resources`, `limits`]
- **Description**: Ensures containers have resource limits defined
- **Fix**: Define CPU and memory limits to prevent resource exhaustion attacks

#### k8s-pod-privileged-container
- **Severity**: 🚨 Critical
- **Category**: Security
- **Tags**: [`pod`, `privileged`, `container-security`]
- **Description**: Detects privileged containers
- **Fix**: Set privileged = false or remove privileged flag

#### k8s-pod-run-as-root
- **Severity**: ⚠️ High
- **Category**: Security
- **Tags**: [`pod`, `root`, `container-security`]
- **Description**: Detects containers running as root user
- **Fix**: Set run_as_user to non-zero value

### 🔐 RBAC Security Rules

#### k8s-rbac-cluster-admin
- **Severity**: ⚠️ High
- **Category**: Security
- **Tags**: [`rbac`, `cluster-admin`, `permissions`]
- **Description**: Detects excessive cluster-admin permissions
- **Fix**: Use more specific roles instead of cluster-admin

#### k8s-rbac-wildcard-permissions
- **Severity**: ⚠️ High
- **Category**: Security
- **Tags**: [`rbac`, `wildcard`, `permissions`]
- **Description**: Detects wildcard permissions in RBAC rules
- **Fix**: Specify explicit resources and verbs

### 🌐 Network Policy Rules

#### k8s-network-policy-default-deny
- **Severity**: ⚡ Medium
- **Category**: Security
- **Tags**: [`network-policy`, `default-deny`, `network-security`]
- **Description**: Recommends default deny network policies
- **Fix**: Create network policy with default deny for ingress/egress

## 🔧 Generic Rules (15+ Cross-Platform Rules)

### 📊 Resource Management

#### MISSING_TAGS
- **Severity**: ℹ️ Low
- **Category**: Best Practices
- **Tags**: [`tagging`, `organization`, `cost-tracking`]
- **Description**: Resources should be tagged for better organization and cost tracking
- **Fix**: Add appropriate tags (Environment, Project, Owner, etc.)

#### DEPRECATED_RESOURCES
- **Severity**: ⚡ Medium
- **Category**: Maintenance
- **Tags**: [`deprecated`, `lifecycle`, `modernization`]
- **Description**: Detects usage of deprecated resource types
- **Fix**: Migrate to recommended resource types

### 🔒 Security Compliance

#### ENCRYPTION_COMPLIANCE
- **Severity**: 🚨 Critical
- **Category**: Compliance
- **Tags**: [`encryption`, `compliance`, `data-protection`]
- **Description**: Ensures encryption is enabled for compliance (HIPAA, SOC2, PCI-DSS)
- **Fix**: Enable encryption for all data stores and transmission

#### SECRET_DETECTION
- **Severity**: 🚨 Critical
- **Category**: Security
- **Tags**: [`secrets`, `credentials`, `exposure`]
- **Description**: Detects potential hardcoded secrets and credentials
- **Fix**: Use secure secret management services

## 🎛️ Rule Configuration

### Global Configuration
```yaml
# .tflint.yml
rules:
  # Global settings
  default_severity: "medium"
  fail_on_critical: true
  fail_on_high: true
  
  # Provider-specific settings
  aws:
    enabled: true
    regions: ["us-east-1", "us-west-2"]
  
  azure:
    enabled: true
    subscriptions: ["subscription-id-1"]
  
  gcp:
    enabled: true
    projects: ["project-id-1"]
  
  kubernetes:
    enabled: true
    contexts: ["prod-cluster"]
```

### Rule-Specific Configuration
```yaml
rules:
  settings:
    aws-s3-bucket-public-read:
      severity: "critical"
      exceptions: ["public-website-*"]
      
    azure-storage-account-https-only:
      severity: "high"
      enforce_all_accounts: true
      
    gcp-compute-instance-public-ip:
      severity: "medium"
      allowed_zones: ["us-central1-a"]
      
    k8s-pod-security-context:
      severity: "medium"
      required_fields: ["runAsNonRoot", "readOnlyRootFilesystem"]
```

### Custom Rule Integration
```yaml
custom_rules:
  - name: "company-naming-convention"
    severity: "low"
    pattern: "^(dev|staging|prod)-.*"
    resources: ["aws_instance", "azurerm_virtual_machine"]
    
  - name: "cost-center-tagging"
    severity: "medium"
    required_tags: ["CostCenter", "Environment", "Owner"]
    exceptions: ["test-*", "*-temp"]
```

## 📈 Performance & Benchmarks

### Rule Execution Performance
- **Average execution time**: ~10μs per rule
- **Memory usage**: ~50MB for 1000+ resources
- **Parallel processing**: Scales with CPU cores
- **Caching**: 3-5x faster on subsequent runs

### Coverage Statistics
- **Total Rules**: 100+
- **Security Rules**: 70+ (70%)
- **Compliance Rules**: 20+ (20%)
- **Best Practice Rules**: 15+ (15%)
- **Test Coverage**: 70%+ across all rules

---

**📚 For more detailed documentation, see:**
- [Configuration Guide](CONFIGURATION.md)
- [Development Guide](DEVELOPMENT.md)
- [API Reference](API.md)
- [Troubleshooting](TROUBLESHOOTING.md) 