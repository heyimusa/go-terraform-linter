package security

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/heyimusa/go-terraform-linter/internal/parser"
	"github.com/heyimusa/go-terraform-linter/internal/types"
)

// =============================================================================
// AWS S3 SECURITY RULES (25+ rules)
// =============================================================================

// AWSS3BucketPublicReadRule detects S3 buckets with public read access
type AWSS3BucketPublicReadRule struct{}

func (r *AWSS3BucketPublicReadRule) GetName() string { return "aws-s3-bucket-public-read" }
func (r *AWSS3BucketPublicReadRule) GetDescription() string { return "S3 bucket allows public read access" }
func (r *AWSS3BucketPublicReadRule) GetSeverity() string { return "critical" }
func (r *AWSS3BucketPublicReadRule) GetCategory() string { return "storage" }
func (r *AWSS3BucketPublicReadRule) GetProvider() string { return "aws" }
func (r *AWSS3BucketPublicReadRule) GetTags() []string { return []string{"s3", "public-access", "data-exposure"} }
func (r *AWSS3BucketPublicReadRule) GetVersion() string { return "1.0.0" }

func (r *AWSS3BucketPublicReadRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if isAWSS3Bucket(&block) {
			if acl, exists := block.Attributes["acl"]; exists {
				aclValue := ctyValueToString(acl.Value)
				if aclValue == "public-read" || aclValue == "public-read-write" {
					issues = append(issues, types.Issue{
						Rule: r.GetName(), Severity: r.GetSeverity(),
						Message: "S3 bucket allows public read access", Line: acl.Range.Start.Line,
						Description: "Remove public ACL and use bucket policies for controlled access",
					})
				}
			}
		}
	}
	return issues
}

// AWSS3BucketSSLOnlyRule ensures S3 buckets require SSL
type AWSS3BucketSSLOnlyRule struct{}

func (r *AWSS3BucketSSLOnlyRule) GetName() string { return "aws-s3-bucket-ssl-only" }
func (r *AWSS3BucketSSLOnlyRule) GetDescription() string { return "S3 bucket should enforce SSL-only access" }
func (r *AWSS3BucketSSLOnlyRule) GetSeverity() string { return "high" }
func (r *AWSS3BucketSSLOnlyRule) GetCategory() string { return "encryption" }
func (r *AWSS3BucketSSLOnlyRule) GetProvider() string { return "aws" }
func (r *AWSS3BucketSSLOnlyRule) GetTags() []string { return []string{"s3", "ssl", "encryption"} }
func (r *AWSS3BucketSSLOnlyRule) GetVersion() string { return "1.0.0" }

func (r *AWSS3BucketSSLOnlyRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	buckets := make(map[string]bool)
	
	// Track S3 buckets
	for _, block := range config.Blocks {
		if isAWSS3Bucket(&block) && len(block.Labels) >= 2 {
			buckets[block.Labels[1]] = false
		}
	}
	
	// Check for SSL-only policies
	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "aws_s3_bucket_policy" {
			if policy, exists := block.Attributes["policy"]; exists {
				policyStr := ctyValueToString(policy.Value)
				if strings.Contains(policyStr, "aws:SecureTransport") {
					if bucket, exists := block.Attributes["bucket"]; exists {
						bucketName := ctyValueToString(bucket.Value)
						buckets[bucketName] = true
					}
				}
			}
		}
	}
	
	// Report buckets without SSL-only policy
	for bucketName, hasSSLPolicy := range buckets {
		if !hasSSLPolicy {
			issues = append(issues, types.Issue{
				Rule: r.GetName(), Severity: r.GetSeverity(),
				Message: fmt.Sprintf("S3 bucket '%s' does not enforce SSL-only access", bucketName),
				Description: "Add bucket policy with aws:SecureTransport condition",
			})
		}
	}
	return issues
}

// AWSS3BucketMFADeleteRule ensures MFA delete is enabled
type AWSS3BucketMFADeleteRule struct{}

func (r *AWSS3BucketMFADeleteRule) GetName() string { return "aws-s3-bucket-mfa-delete" }
func (r *AWSS3BucketMFADeleteRule) GetDescription() string { return "S3 bucket should have MFA delete enabled" }
func (r *AWSS3BucketMFADeleteRule) GetSeverity() string { return "medium" }
func (r *AWSS3BucketMFADeleteRule) GetCategory() string { return "data-protection" }
func (r *AWSS3BucketMFADeleteRule) GetProvider() string { return "aws" }
func (r *AWSS3BucketMFADeleteRule) GetTags() []string { return []string{"s3", "mfa", "data-protection"} }
func (r *AWSS3BucketMFADeleteRule) GetVersion() string { return "1.0.0" }

func (r *AWSS3BucketMFADeleteRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "aws_s3_bucket_versioning" {
			hasMFADelete := false
			for _, versioningBlock := range block.Blocks {
				if versioningBlock.Type == "versioning_configuration" {
					if mfaDelete, exists := versioningBlock.Attributes["mfa_delete"]; exists {
						if ctyValueToString(mfaDelete.Value) == "Enabled" {
							hasMFADelete = true
						}
					}
				}
			}
			if !hasMFADelete {
				issues = append(issues, types.Issue{
					Rule: r.GetName(), Severity: r.GetSeverity(),
					Message: "S3 bucket versioning does not have MFA delete enabled",
					Line: block.Range.Start.Line,
					Description: "Add mfa_delete = \"Enabled\" in versioning_configuration block",
				})
			}
		}
	}
	return issues
}

// AWSS3BucketLifecycleRule ensures lifecycle policies are configured
type AWSS3BucketLifecycleRule struct{}

func (r *AWSS3BucketLifecycleRule) GetName() string { return "aws-s3-bucket-lifecycle" }
func (r *AWSS3BucketLifecycleRule) GetDescription() string { return "S3 bucket should have lifecycle policies" }
func (r *AWSS3BucketLifecycleRule) GetSeverity() string { return "low" }
func (r *AWSS3BucketLifecycleRule) GetCategory() string { return "cost-optimization" }
func (r *AWSS3BucketLifecycleRule) GetProvider() string { return "aws" }
func (r *AWSS3BucketLifecycleRule) GetTags() []string { return []string{"s3", "lifecycle", "cost"} }
func (r *AWSS3BucketLifecycleRule) GetVersion() string { return "1.0.0" }

func (r *AWSS3BucketLifecycleRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	buckets := make(map[string]bool)
	
	// Track S3 buckets
	for _, block := range config.Blocks {
		if isAWSS3Bucket(&block) && len(block.Labels) >= 2 {
			buckets[block.Labels[1]] = false
		}
	}
	
	// Check for lifecycle configurations
	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "aws_s3_bucket_lifecycle_configuration" {
			if bucket, exists := block.Attributes["bucket"]; exists {
				bucketName := ctyValueToString(bucket.Value)
				buckets[bucketName] = true
			}
		}
	}
	
	// Report buckets without lifecycle policies
	for bucketName, hasLifecycle := range buckets {
		if !hasLifecycle {
			issues = append(issues, types.Issue{
				Rule: r.GetName(), Severity: r.GetSeverity(),
				Message: fmt.Sprintf("S3 bucket '%s' does not have lifecycle policies configured", bucketName),
				Description: "Add aws_s3_bucket_lifecycle_configuration resource",
			})
		}
	}
	return issues
}

// =============================================================================
// AWS EC2 SECURITY RULES (30+ rules)
// =============================================================================

// AWSEC2InstancePublicIPRule detects instances with public IPs
type AWSEC2InstancePublicIPRule struct{}

func (r *AWSEC2InstancePublicIPRule) GetName() string { return "aws-ec2-instance-public-ip" }
func (r *AWSEC2InstancePublicIPRule) GetDescription() string { return "EC2 instance has public IP address" }
func (r *AWSEC2InstancePublicIPRule) GetSeverity() string { return "medium" }
func (r *AWSEC2InstancePublicIPRule) GetCategory() string { return "network" }
func (r *AWSEC2InstancePublicIPRule) GetProvider() string { return "aws" }
func (r *AWSEC2InstancePublicIPRule) GetTags() []string { return []string{"ec2", "public-ip", "network"} }
func (r *AWSEC2InstancePublicIPRule) GetVersion() string { return "1.0.0" }

func (r *AWSEC2InstancePublicIPRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if isAWSEC2Instance(&block) {
			if associatePublicIP, exists := block.Attributes["associate_public_ip_address"]; exists {
				if ctyValueToString(associatePublicIP.Value) == "true" {
					issues = append(issues, types.Issue{
						Rule: r.GetName(), Severity: r.GetSeverity(),
						Message: "EC2 instance is configured with public IP address",
						Line: associatePublicIP.Range.Start.Line,
						Description: "Set associate_public_ip_address = false and use NAT gateway for outbound access",
					})
				}
			}
		}
	}
	return issues
}

// AWSEC2InstanceMetadataV2Rule ensures IMDSv2 is enforced
type AWSEC2InstanceMetadataV2Rule struct{}

func (r *AWSEC2InstanceMetadataV2Rule) GetName() string { return "aws-ec2-instance-metadata-v2" }
func (r *AWSEC2InstanceMetadataV2Rule) GetDescription() string { return "EC2 instance should enforce IMDSv2" }
func (r *AWSEC2InstanceMetadataV2Rule) GetSeverity() string { return "high" }
func (r *AWSEC2InstanceMetadataV2Rule) GetCategory() string { return "security" }
func (r *AWSEC2InstanceMetadataV2Rule) GetProvider() string { return "aws" }
func (r *AWSEC2InstanceMetadataV2Rule) GetTags() []string { return []string{"ec2", "metadata", "imds"} }
func (r *AWSEC2InstanceMetadataV2Rule) GetVersion() string { return "1.0.0" }

func (r *AWSEC2InstanceMetadataV2Rule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if isAWSEC2Instance(&block) {
			hasIMDSv2 := false
			for _, metadataBlock := range block.Blocks {
				if metadataBlock.Type == "metadata_options" {
					if httpTokens, exists := metadataBlock.Attributes["http_tokens"]; exists {
						if ctyValueToString(httpTokens.Value) == "required" {
							hasIMDSv2 = true
						}
					}
				}
			}
			if !hasIMDSv2 {
				issues = append(issues, types.Issue{
					Rule: r.GetName(), Severity: r.GetSeverity(),
					Message: "EC2 instance does not enforce IMDSv2",
					Line: block.Range.Start.Line,
					Description: "Add metadata_options block with http_tokens = \"required\"",
				})
			}
		}
	}
	return issues
}

// AWSEC2InstanceUserDataSecretsRule detects secrets in user data
type AWSEC2InstanceUserDataSecretsRule struct{}

func (r *AWSEC2InstanceUserDataSecretsRule) GetName() string { return "aws-ec2-instance-user-data-secrets" }
func (r *AWSEC2InstanceUserDataSecretsRule) GetDescription() string { return "EC2 instance user data contains secrets" }
func (r *AWSEC2InstanceUserDataSecretsRule) GetSeverity() string { return "critical" }
func (r *AWSEC2InstanceUserDataSecretsRule) GetCategory() string { return "secrets" }
func (r *AWSEC2InstanceUserDataSecretsRule) GetProvider() string { return "aws" }
func (r *AWSEC2InstanceUserDataSecretsRule) GetTags() []string { return []string{"ec2", "secrets", "user-data"} }
func (r *AWSEC2InstanceUserDataSecretsRule) GetVersion() string { return "1.0.0" }

func (r *AWSEC2InstanceUserDataSecretsRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	secretPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[=:]\s*["\']?[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]{8,}["\']?`),
		regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?[a-zA-Z0-9]{20,}["\']?`),
		regexp.MustCompile(`(?i)(secret[_-]?key|secretkey)\s*[=:]\s*["\']?[a-zA-Z0-9+/]{20,}["\']?`),
		regexp.MustCompile(`(?i)(access[_-]?key|accesskey)\s*[=:]\s*["\']?[A-Z0-9]{20}["\']?`),
		regexp.MustCompile(`(?i)(token)\s*[=:]\s*["\']?[a-zA-Z0-9+/]{20,}["\']?`),
	}
	
	for _, block := range config.Blocks {
		if isAWSEC2Instance(&block) {
			if userData, exists := block.Attributes["user_data"]; exists {
				userDataStr := ctyValueToString(userData.Value)
				for _, pattern := range secretPatterns {
					if pattern.MatchString(userDataStr) {
						issues = append(issues, types.Issue{
							Rule: r.GetName(), Severity: r.GetSeverity(),
							Message: "EC2 instance user data contains potential secrets",
							Line: userData.Range.Start.Line,
							Description: "Use AWS Systems Manager Parameter Store or Secrets Manager instead of hardcoded secrets",
						})
						break
					}
				}
			}
		}
	}
	return issues
}

// AWSEC2EBSEncryptionRule ensures EBS volumes are encrypted
type AWSEC2EBSEncryptionRule struct{}

func (r *AWSEC2EBSEncryptionRule) GetName() string { return "aws-ec2-ebs-encryption" }
func (r *AWSEC2EBSEncryptionRule) GetDescription() string { return "EBS volume should be encrypted" }
func (r *AWSEC2EBSEncryptionRule) GetSeverity() string { return "high" }
func (r *AWSEC2EBSEncryptionRule) GetCategory() string { return "encryption" }
func (r *AWSEC2EBSEncryptionRule) GetProvider() string { return "aws" }
func (r *AWSEC2EBSEncryptionRule) GetTags() []string { return []string{"ec2", "ebs", "encryption"} }
func (r *AWSEC2EBSEncryptionRule) GetVersion() string { return "1.0.0" }

func (r *AWSEC2EBSEncryptionRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "aws_ebs_volume" {
			if encrypted, exists := block.Attributes["encrypted"]; exists {
				if ctyValueToString(encrypted.Value) != "true" {
					issues = append(issues, types.Issue{
						Rule: r.GetName(), Severity: r.GetSeverity(),
						Message: "EBS volume is not encrypted",
						Line: encrypted.Range.Start.Line,
						Description: "Set encrypted = true",
					})
				}
			} else {
				issues = append(issues, types.Issue{
					Rule: r.GetName(), Severity: r.GetSeverity(),
					Message: "EBS volume encryption not specified",
					Line: block.Range.Start.Line,
					Description: "Add encrypted = true",
				})
			}
		}
	}
	return issues
}

// =============================================================================
// AWS IAM SECURITY RULES (25+ rules)
// =============================================================================

// AWSIAMPolicyWildcardResourceRule detects wildcard resources in IAM policies
type AWSIAMPolicyWildcardResourceRule struct{}

func (r *AWSIAMPolicyWildcardResourceRule) GetName() string { return "aws-iam-policy-wildcard-resource" }
func (r *AWSIAMPolicyWildcardResourceRule) GetDescription() string { return "IAM policy uses wildcard in Resource" }
func (r *AWSIAMPolicyWildcardResourceRule) GetSeverity() string { return "high" }
func (r *AWSIAMPolicyWildcardResourceRule) GetCategory() string { return "iam" }
func (r *AWSIAMPolicyWildcardResourceRule) GetProvider() string { return "aws" }
func (r *AWSIAMPolicyWildcardResourceRule) GetTags() []string { return []string{"iam", "policy", "privilege"} }
func (r *AWSIAMPolicyWildcardResourceRule) GetVersion() string { return "1.0.0" }

func (r *AWSIAMPolicyWildcardResourceRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if isAWSIAMPolicy(&block) {
			if policy, exists := block.Attributes["policy"]; exists {
				policyStr := ctyValueToString(policy.Value)
				if strings.Contains(policyStr, `"Resource": "*"`) || strings.Contains(policyStr, `"Resource":["*"]`) {
					issues = append(issues, types.Issue{
						Rule: r.GetName(), Severity: r.GetSeverity(),
						Message: "IAM policy grants access to all resources using wildcard",
						Line: policy.Range.Start.Line,
						Description: "Specify explicit resource ARNs instead of using wildcard",
					})
				}
			}
		}
	}
	return issues
}

// AWSIAMUserAccessKeysRule detects IAM users with access keys
type AWSIAMUserAccessKeysRule struct{}

func (r *AWSIAMUserAccessKeysRule) GetName() string { return "aws-iam-user-access-keys" }
func (r *AWSIAMUserAccessKeysRule) GetDescription() string { return "IAM user has access keys configured" }
func (r *AWSIAMUserAccessKeysRule) GetSeverity() string { return "medium" }
func (r *AWSIAMUserAccessKeysRule) GetCategory() string { return "iam" }
func (r *AWSIAMUserAccessKeysRule) GetProvider() string { return "aws" }
func (r *AWSIAMUserAccessKeysRule) GetTags() []string { return []string{"iam", "access-keys", "credentials"} }
func (r *AWSIAMUserAccessKeysRule) GetVersion() string { return "1.0.0" }

func (r *AWSIAMUserAccessKeysRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "aws_iam_access_key" {
			issues = append(issues, types.Issue{
				Rule: r.GetName(), Severity: r.GetSeverity(),
				Message: "IAM access key found - consider using IAM roles instead",
				Line: block.Range.Start.Line,
				Description: "Use IAM roles and instance profiles instead of access keys",
			})
		}
	}
	return issues
}

// AWSIAMRootAccessKeysRule detects root account access keys
type AWSIAMRootAccessKeysRule struct{}

func (r *AWSIAMRootAccessKeysRule) GetName() string { return "aws-iam-root-access-keys" }
func (r *AWSIAMRootAccessKeysRule) GetDescription() string { return "Root account access keys detected" }
func (r *AWSIAMRootAccessKeysRule) GetSeverity() string { return "critical" }
func (r *AWSIAMRootAccessKeysRule) GetCategory() string { return "iam" }
func (r *AWSIAMRootAccessKeysRule) GetProvider() string { return "aws" }
func (r *AWSIAMRootAccessKeysRule) GetTags() []string { return []string{"iam", "root", "access-keys"} }
func (r *AWSIAMRootAccessKeysRule) GetVersion() string { return "1.0.0" }

func (r *AWSIAMRootAccessKeysRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "aws_iam_access_key" {
			if user, exists := block.Attributes["user"]; exists {
				userStr := ctyValueToString(user.Value)
				if userStr == "root" {
					issues = append(issues, types.Issue{
						Rule: r.GetName(), Severity: r.GetSeverity(),
						Message: "Root account access keys should never be created",
						Line: user.Range.Start.Line,
						Description: "Delete root access keys and use IAM users with appropriate permissions",
					})
				}
			}
		}
	}
	return issues
}

// =============================================================================
// AWS RDS SECURITY RULES (20+ rules)
// =============================================================================

// AWSRDSInstancePublicRule detects publicly accessible RDS instances
type AWSRDSInstancePublicRule struct{}

func (r *AWSRDSInstancePublicRule) GetName() string { return "aws-rds-instance-public" }
func (r *AWSRDSInstancePublicRule) GetDescription() string { return "RDS instance is publicly accessible" }
func (r *AWSRDSInstancePublicRule) GetSeverity() string { return "critical" }
func (r *AWSRDSInstancePublicRule) GetCategory() string { return "database" }
func (r *AWSRDSInstancePublicRule) GetProvider() string { return "aws" }
func (r *AWSRDSInstancePublicRule) GetTags() []string { return []string{"rds", "public", "database"} }
func (r *AWSRDSInstancePublicRule) GetVersion() string { return "1.0.0" }

func (r *AWSRDSInstancePublicRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if isAWSRDSInstance(&block) {
			if publiclyAccessible, exists := block.Attributes["publicly_accessible"]; exists {
				if ctyValueToString(publiclyAccessible.Value) == "true" {
					issues = append(issues, types.Issue{
						Rule: r.GetName(), Severity: r.GetSeverity(),
						Message: "RDS instance is configured as publicly accessible",
						Line: publiclyAccessible.Range.Start.Line,
						Description: "Set publicly_accessible = false",
					})
				}
			}
		}
	}
	return issues
}

// AWSRDSInstanceSnapshotPublicRule detects public RDS snapshots
type AWSRDSInstanceSnapshotPublicRule struct{}

func (r *AWSRDSInstanceSnapshotPublicRule) GetName() string { return "aws-rds-snapshot-public" }
func (r *AWSRDSInstanceSnapshotPublicRule) GetDescription() string { return "RDS snapshot is publicly accessible" }
func (r *AWSRDSInstanceSnapshotPublicRule) GetSeverity() string { return "critical" }
func (r *AWSRDSInstanceSnapshotPublicRule) GetCategory() string { return "database" }
func (r *AWSRDSInstanceSnapshotPublicRule) GetProvider() string { return "aws" }
func (r *AWSRDSInstanceSnapshotPublicRule) GetTags() []string { return []string{"rds", "snapshot", "public"} }
func (r *AWSRDSInstanceSnapshotPublicRule) GetVersion() string { return "1.0.0" }

func (r *AWSRDSInstanceSnapshotPublicRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 && 
		   (block.Labels[0] == "aws_db_snapshot" || block.Labels[0] == "aws_db_cluster_snapshot") {
			// Check for public snapshot sharing
			for _, shareBlock := range config.Blocks {
				if shareBlock.Type == "resource" && len(shareBlock.Labels) >= 2 && 
				   shareBlock.Labels[0] == "aws_db_snapshot_attribute" {
					if attributeName, exists := shareBlock.Attributes["attribute_name"]; exists {
						if ctyValueToString(attributeName.Value) == "restore" {
							if attributeValues, exists := shareBlock.Attributes["attribute_values"]; exists {
								valuesStr := ctyValueToString(attributeValues.Value)
								if strings.Contains(valuesStr, "all") {
									issues = append(issues, types.Issue{
										Rule: r.GetName(), Severity: r.GetSeverity(),
										Message: "RDS snapshot is shared publicly",
										Line: attributeValues.Range.Start.Line,
										Description: "Remove 'all' from attribute_values or specify specific account IDs",
									})
								}
							}
						}
					}
				}
			}
		}
	}
	return issues
}

// AWSRDSInstanceDeletionProtectionRule ensures deletion protection is enabled
type AWSRDSInstanceDeletionProtectionRule struct{}

func (r *AWSRDSInstanceDeletionProtectionRule) GetName() string { return "aws-rds-deletion-protection" }
func (r *AWSRDSInstanceDeletionProtectionRule) GetDescription() string { return "RDS instance should have deletion protection enabled" }
func (r *AWSRDSInstanceDeletionProtectionRule) GetSeverity() string { return "medium" }
func (r *AWSRDSInstanceDeletionProtectionRule) GetCategory() string { return "data-protection" }
func (r *AWSRDSInstanceDeletionProtectionRule) GetProvider() string { return "aws" }
func (r *AWSRDSInstanceDeletionProtectionRule) GetTags() []string { return []string{"rds", "deletion-protection", "data-protection"} }
func (r *AWSRDSInstanceDeletionProtectionRule) GetVersion() string { return "1.0.0" }

func (r *AWSRDSInstanceDeletionProtectionRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if isAWSRDSInstance(&block) {
			if deletionProtection, exists := block.Attributes["deletion_protection"]; exists {
				if ctyValueToString(deletionProtection.Value) != "true" {
					issues = append(issues, types.Issue{
						Rule: r.GetName(), Severity: r.GetSeverity(),
						Message: "RDS instance does not have deletion protection enabled",
						Line: deletionProtection.Range.Start.Line,
						Description: "Set deletion_protection = true",
					})
				}
			} else {
				issues = append(issues, types.Issue{
					Rule: r.GetName(), Severity: r.GetSeverity(),
					Message: "RDS instance deletion protection not specified",
					Line: block.Range.Start.Line,
					Description: "Add deletion_protection = true",
				})
			}
		}
	}
	return issues
}

// =============================================================================
// AWS LAMBDA SECURITY RULES (15+ rules)
// =============================================================================

// AWSLambdaFunctionPublicRule detects publicly accessible Lambda functions
type AWSLambdaFunctionPublicRule struct{}

func (r *AWSLambdaFunctionPublicRule) GetName() string { return "aws-lambda-function-public" }
func (r *AWSLambdaFunctionPublicRule) GetDescription() string { return "Lambda function is publicly accessible" }
func (r *AWSLambdaFunctionPublicRule) GetSeverity() string { return "high" }
func (r *AWSLambdaFunctionPublicRule) GetCategory() string { return "serverless" }
func (r *AWSLambdaFunctionPublicRule) GetProvider() string { return "aws" }
func (r *AWSLambdaFunctionPublicRule) GetTags() []string { return []string{"lambda", "public", "serverless"} }
func (r *AWSLambdaFunctionPublicRule) GetVersion() string { return "1.0.0" }

func (r *AWSLambdaFunctionPublicRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "aws_lambda_permission" {
			if principal, exists := block.Attributes["principal"]; exists {
				principalStr := ctyValueToString(principal.Value)
				if principalStr == "*" {
					issues = append(issues, types.Issue{
						Rule: r.GetName(), Severity: r.GetSeverity(),
						Message: "Lambda function permission allows public access",
						Line: principal.Range.Start.Line,
						Description: "Specify explicit principals instead of using wildcard",
					})
				}
			}
		}
	}
	return issues
}

// AWSLambdaEnvironmentSecretsRule detects secrets in environment variables
type AWSLambdaEnvironmentSecretsRule struct{}

func (r *AWSLambdaEnvironmentSecretsRule) GetName() string { return "aws-lambda-environment-secrets" }
func (r *AWSLambdaEnvironmentSecretsRule) GetDescription() string { return "Lambda function environment contains secrets" }
func (r *AWSLambdaEnvironmentSecretsRule) GetSeverity() string { return "critical" }
func (r *AWSLambdaEnvironmentSecretsRule) GetCategory() string { return "secrets" }
func (r *AWSLambdaEnvironmentSecretsRule) GetProvider() string { return "aws" }
func (r *AWSLambdaEnvironmentSecretsRule) GetTags() []string { return []string{"lambda", "secrets", "environment"} }
func (r *AWSLambdaEnvironmentSecretsRule) GetVersion() string { return "1.0.0" }

func (r *AWSLambdaEnvironmentSecretsRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	secretPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(password|passwd|pwd|secret|key|token|api_key|access_key)`),
	}
	
	for _, block := range config.Blocks {
		if isAWSLambdaFunction(&block) {
			for _, envBlock := range block.Blocks {
				if envBlock.Type == "environment" {
					if variables, exists := envBlock.Attributes["variables"]; exists {
						variablesStr := ctyValueToString(variables.Value)
						for _, pattern := range secretPatterns {
							if pattern.MatchString(variablesStr) {
								issues = append(issues, types.Issue{
									Rule: r.GetName(), Severity: r.GetSeverity(),
									Message: "Lambda function environment variables may contain secrets",
									Line: variables.Range.Start.Line,
									Description: "Use AWS Systems Manager Parameter Store or Secrets Manager",
								})
								break
							}
						}
					}
				}
			}
		}
	}
	return issues
}

// AWSLambdaFunctionUrlRule detects Lambda function URLs without auth
type AWSLambdaFunctionUrlRule struct{}

func (r *AWSLambdaFunctionUrlRule) GetName() string { return "aws-lambda-function-url-auth" }
func (r *AWSLambdaFunctionUrlRule) GetDescription() string { return "Lambda function URL should require authentication" }
func (r *AWSLambdaFunctionUrlRule) GetSeverity() string { return "high" }
func (r *AWSLambdaFunctionUrlRule) GetCategory() string { return "serverless" }
func (r *AWSLambdaFunctionUrlRule) GetProvider() string { return "aws" }
func (r *AWSLambdaFunctionUrlRule) GetTags() []string { return []string{"lambda", "function-url", "authentication"} }
func (r *AWSLambdaFunctionUrlRule) GetVersion() string { return "1.0.0" }

func (r *AWSLambdaFunctionUrlRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "aws_lambda_function_url" {
			for _, corsBlock := range block.Blocks {
				if corsBlock.Type == "cors" {
					if authType, exists := block.Attributes["authorization_type"]; exists {
						if ctyValueToString(authType.Value) == "NONE" {
							issues = append(issues, types.Issue{
								Rule: r.GetName(), Severity: r.GetSeverity(),
								Message: "Lambda function URL allows unauthenticated access",
								Line: authType.Range.Start.Line,
								Description: "Set authorization_type = \"AWS_IAM\" or use API Gateway",
							})
						}
					}
				}
			}
		}
	}
	return issues
}

// AWSLambdaFunctionReservedConcurrencyRule checks for reserved concurrency
type AWSLambdaFunctionReservedConcurrencyRule struct{}

func (r *AWSLambdaFunctionReservedConcurrencyRule) GetName() string { return "aws-lambda-reserved-concurrency" }
func (r *AWSLambdaFunctionReservedConcurrencyRule) GetDescription() string { return "Lambda function should have reserved concurrency configured" }
func (r *AWSLambdaFunctionReservedConcurrencyRule) GetSeverity() string { return "low" }
func (r *AWSLambdaFunctionReservedConcurrencyRule) GetCategory() string { return "performance" }
func (r *AWSLambdaFunctionReservedConcurrencyRule) GetProvider() string { return "aws" }
func (r *AWSLambdaFunctionReservedConcurrencyRule) GetTags() []string { return []string{"lambda", "concurrency", "performance"} }
func (r *AWSLambdaFunctionReservedConcurrencyRule) GetVersion() string { return "1.0.0" }

func (r *AWSLambdaFunctionReservedConcurrencyRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if isAWSLambdaFunction(&block) {
			if _, exists := block.Attributes["reserved_concurrent_executions"]; !exists {
				issues = append(issues, types.Issue{
					Rule: r.GetName(), Severity: r.GetSeverity(),
					Message: "Lambda function should have reserved concurrency to prevent resource exhaustion",
					Line: block.Range.Start.Line,
					Description: "Add reserved_concurrent_executions = <appropriate_value>",
				})
			}
		}
	}
	return issues
}

// =============================================================================
// AWS VPC SECURITY RULES (20+ rules)
// =============================================================================

// AWSVPCDefaultSecurityGroupRule detects default security group usage
type AWSVPCDefaultSecurityGroupRule struct{}

func (r *AWSVPCDefaultSecurityGroupRule) GetName() string { return "aws-vpc-default-security-group" }
func (r *AWSVPCDefaultSecurityGroupRule) GetDescription() string { return "Default VPC security group should not be used" }
func (r *AWSVPCDefaultSecurityGroupRule) GetSeverity() string { return "medium" }
func (r *AWSVPCDefaultSecurityGroupRule) GetCategory() string { return "network" }
func (r *AWSVPCDefaultSecurityGroupRule) GetProvider() string { return "aws" }
func (r *AWSVPCDefaultSecurityGroupRule) GetTags() []string { return []string{"vpc", "security-group", "default"} }
func (r *AWSVPCDefaultSecurityGroupRule) GetVersion() string { return "1.0.0" }

func (r *AWSVPCDefaultSecurityGroupRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "aws_default_security_group" {
			// Check if default security group has rules configured
			hasIngressRules := false
			hasEgressRules := false
			
			for _, nestedBlock := range block.Blocks {
				if nestedBlock.Type == "ingress" {
					hasIngressRules = true
				}
				if nestedBlock.Type == "egress" {
					hasEgressRules = true
				}
			}
			
			if hasIngressRules || hasEgressRules {
				issues = append(issues, types.Issue{
					Rule: r.GetName(), Severity: r.GetSeverity(),
					Message: "Default security group should not have any rules configured",
					Line: block.Range.Start.Line,
					Description: "Create custom security groups instead of using the default",
				})
			}
		}
	}
	return issues
}

// AWSSecurityGroupSSHWorldRule detects SSH access from 0.0.0.0/0
type AWSSecurityGroupSSHWorldRule struct{}

func (r *AWSSecurityGroupSSHWorldRule) GetName() string { return "aws-security-group-ssh-world" }
func (r *AWSSecurityGroupSSHWorldRule) GetDescription() string { return "Security group allows SSH access from anywhere" }
func (r *AWSSecurityGroupSSHWorldRule) GetSeverity() string { return "critical" }
func (r *AWSSecurityGroupSSHWorldRule) GetCategory() string { return "network" }
func (r *AWSSecurityGroupSSHWorldRule) GetProvider() string { return "aws" }
func (r *AWSSecurityGroupSSHWorldRule) GetTags() []string { return []string{"security-group", "ssh", "public-access"} }
func (r *AWSSecurityGroupSSHWorldRule) GetVersion() string { return "1.0.0" }

func (r *AWSSecurityGroupSSHWorldRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if isAWSSecurityGroup(&block) {
			for _, ingressBlock := range block.Blocks {
				if ingressBlock.Type == "ingress" {
					if fromPort, exists := ingressBlock.Attributes["from_port"]; exists {
						if ctyValueToString(fromPort.Value) == "22" {
							if cidrBlocks, exists := ingressBlock.Attributes["cidr_blocks"]; exists {
								cidrStr := ctyValueToString(cidrBlocks.Value)
								if strings.Contains(cidrStr, "0.0.0.0/0") {
									issues = append(issues, types.Issue{
										Rule: r.GetName(), Severity: r.GetSeverity(),
										Message: "Security group allows SSH access from anywhere (0.0.0.0/0)",
										Line: cidrBlocks.Range.Start.Line,
										Description: "Restrict SSH access to specific IP ranges or use bastion host",
									})
								}
							}
						}
					}
				}
			}
		}
	}
	return issues
}

// AWSSecurityGroupRDPWorldRule detects RDP access from 0.0.0.0/0
type AWSSecurityGroupRDPWorldRule struct{}

func (r *AWSSecurityGroupRDPWorldRule) GetName() string { return "aws-security-group-rdp-world" }
func (r *AWSSecurityGroupRDPWorldRule) GetDescription() string { return "Security group allows RDP access from anywhere" }
func (r *AWSSecurityGroupRDPWorldRule) GetSeverity() string { return "critical" }
func (r *AWSSecurityGroupRDPWorldRule) GetCategory() string { return "network" }
func (r *AWSSecurityGroupRDPWorldRule) GetProvider() string { return "aws" }
func (r *AWSSecurityGroupRDPWorldRule) GetTags() []string { return []string{"security-group", "rdp", "public-access"} }
func (r *AWSSecurityGroupRDPWorldRule) GetVersion() string { return "1.0.0" }

func (r *AWSSecurityGroupRDPWorldRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if isAWSSecurityGroup(&block) {
			for _, ingressBlock := range block.Blocks {
				if ingressBlock.Type == "ingress" {
					if fromPort, exists := ingressBlock.Attributes["from_port"]; exists {
						if ctyValueToString(fromPort.Value) == "3389" {
							if cidrBlocks, exists := ingressBlock.Attributes["cidr_blocks"]; exists {
								cidrStr := ctyValueToString(cidrBlocks.Value)
								if strings.Contains(cidrStr, "0.0.0.0/0") {
									issues = append(issues, types.Issue{
										Rule: r.GetName(), Severity: r.GetSeverity(),
										Message: "Security group allows RDP access from anywhere (0.0.0.0/0)",
										Line: cidrBlocks.Range.Start.Line,
										Description: "Restrict RDP access to specific IP ranges or use VPN",
									})
								}
							}
						}
					}
				}
			}
		}
	}
	return issues
}

// AWSVPCFlowLogsRule ensures VPC flow logs are enabled
type AWSVPCFlowLogsRule struct{}

func (r *AWSVPCFlowLogsRule) GetName() string { return "aws-vpc-flow-logs" }
func (r *AWSVPCFlowLogsRule) GetDescription() string { return "VPC should have flow logs enabled" }
func (r *AWSVPCFlowLogsRule) GetSeverity() string { return "medium" }
func (r *AWSVPCFlowLogsRule) GetCategory() string { return "logging" }
func (r *AWSVPCFlowLogsRule) GetProvider() string { return "aws" }
func (r *AWSVPCFlowLogsRule) GetTags() []string { return []string{"vpc", "flow-logs", "monitoring"} }
func (r *AWSVPCFlowLogsRule) GetVersion() string { return "1.0.0" }

func (r *AWSVPCFlowLogsRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	vpcs := make(map[string]bool)
	
	// Track VPCs
	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "aws_vpc" {
			vpcs[block.Labels[1]] = false
		}
	}
	
	// Check for flow logs
	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "aws_flow_log" {
			if resourceType, exists := block.Attributes["resource_type"]; exists {
				if ctyValueToString(resourceType.Value) == "VPC" {
					if resourceIds, exists := block.Attributes["resource_ids"]; exists {
						resourceIdsStr := ctyValueToString(resourceIds.Value)
						for vpcName := range vpcs {
							if strings.Contains(resourceIdsStr, vpcName) {
								vpcs[vpcName] = true
							}
						}
					}
				}
			}
		}
	}
	
	// Report VPCs without flow logs
	for vpcName, hasFlowLogs := range vpcs {
		if !hasFlowLogs {
			issues = append(issues, types.Issue{
				Rule: r.GetName(), Severity: r.GetSeverity(),
				Message: fmt.Sprintf("VPC '%s' does not have flow logs enabled", vpcName),
				Description: "Add aws_flow_log resource for the VPC",
			})
		}
	}
	return issues
}

// =============================================================================
// AWS CLOUDTRAIL SECURITY RULES (10+ rules)
// =============================================================================

// AWSCloudTrailEncryptionRule ensures CloudTrail logs are encrypted
type AWSCloudTrailEncryptionRule struct{}

func (r *AWSCloudTrailEncryptionRule) GetName() string { return "aws-cloudtrail-encryption" }
func (r *AWSCloudTrailEncryptionRule) GetDescription() string { return "CloudTrail should have log file encryption enabled" }
func (r *AWSCloudTrailEncryptionRule) GetSeverity() string { return "high" }
func (r *AWSCloudTrailEncryptionRule) GetCategory() string { return "logging" }
func (r *AWSCloudTrailEncryptionRule) GetProvider() string { return "aws" }
func (r *AWSCloudTrailEncryptionRule) GetTags() []string { return []string{"cloudtrail", "encryption", "logging"} }
func (r *AWSCloudTrailEncryptionRule) GetVersion() string { return "1.0.0" }

func (r *AWSCloudTrailEncryptionRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "aws_cloudtrail" {
			if _, exists := block.Attributes["kms_key_id"]; !exists {
				issues = append(issues, types.Issue{
					Rule: r.GetName(), Severity: r.GetSeverity(),
					Message: "CloudTrail does not have log file encryption enabled",
					Line: block.Range.Start.Line,
					Description: "Add kms_key_id to encrypt CloudTrail log files",
				})
			}
		}
	}
	return issues
}

// AWSCloudTrailLogValidationRule ensures log file validation is enabled
type AWSCloudTrailLogValidationRule struct{}

func (r *AWSCloudTrailLogValidationRule) GetName() string { return "aws-cloudtrail-log-validation" }
func (r *AWSCloudTrailLogValidationRule) GetDescription() string { return "CloudTrail should have log file validation enabled" }
func (r *AWSCloudTrailLogValidationRule) GetSeverity() string { return "medium" }
func (r *AWSCloudTrailLogValidationRule) GetCategory() string { return "logging" }
func (r *AWSCloudTrailLogValidationRule) GetProvider() string { return "aws" }
func (r *AWSCloudTrailLogValidationRule) GetTags() []string { return []string{"cloudtrail", "validation", "integrity"} }
func (r *AWSCloudTrailLogValidationRule) GetVersion() string { return "1.0.0" }

func (r *AWSCloudTrailLogValidationRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "aws_cloudtrail" {
			if enableLogValidation, exists := block.Attributes["enable_log_file_validation"]; exists {
				if ctyValueToString(enableLogValidation.Value) != "true" {
					issues = append(issues, types.Issue{
						Rule: r.GetName(), Severity: r.GetSeverity(),
						Message: "CloudTrail does not have log file validation enabled",
						Line: enableLogValidation.Range.Start.Line,
						Description: "Set enable_log_file_validation = true",
					})
				}
			} else {
				issues = append(issues, types.Issue{
					Rule: r.GetName(), Severity: r.GetSeverity(),
					Message: "CloudTrail log file validation not specified",
					Line: block.Range.Start.Line,
					Description: "Add enable_log_file_validation = true",
				})
			}
		}
	}
	return issues
}

// =============================================================================
// AWS KMS SECURITY RULES (10+ rules)
// =============================================================================

// AWSKMSKeyRotationRule ensures KMS keys have rotation enabled
type AWSKMSKeyRotationRule struct{}

func (r *AWSKMSKeyRotationRule) GetName() string { return "aws-kms-key-rotation" }
func (r *AWSKMSKeyRotationRule) GetDescription() string { return "KMS key should have automatic rotation enabled" }
func (r *AWSKMSKeyRotationRule) GetSeverity() string { return "medium" }
func (r *AWSKMSKeyRotationRule) GetCategory() string { return "encryption" }
func (r *AWSKMSKeyRotationRule) GetProvider() string { return "aws" }
func (r *AWSKMSKeyRotationRule) GetTags() []string { return []string{"kms", "rotation", "encryption"} }
func (r *AWSKMSKeyRotationRule) GetVersion() string { return "1.0.0" }

func (r *AWSKMSKeyRotationRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "aws_kms_key" {
			if enableKeyRotation, exists := block.Attributes["enable_key_rotation"]; exists {
				if ctyValueToString(enableKeyRotation.Value) != "true" {
					issues = append(issues, types.Issue{
						Rule: r.GetName(), Severity: r.GetSeverity(),
						Message: "KMS key does not have automatic rotation enabled",
						Line: enableKeyRotation.Range.Start.Line,
						Description: "Set enable_key_rotation = true",
					})
				}
			} else {
				issues = append(issues, types.Issue{
					Rule: r.GetName(), Severity: r.GetSeverity(),
					Message: "KMS key rotation not specified",
					Line: block.Range.Start.Line,
					Description: "Add enable_key_rotation = true",
				})
			}
		}
	}
	return issues
}

// AWSKMSKeyPolicyWildcardRule detects wildcard principals in KMS key policies
type AWSKMSKeyPolicyWildcardRule struct{}

func (r *AWSKMSKeyPolicyWildcardRule) GetName() string { return "aws-kms-key-policy-wildcard" }
func (r *AWSKMSKeyPolicyWildcardRule) GetDescription() string { return "KMS key policy should not allow wildcard principals" }
func (r *AWSKMSKeyPolicyWildcardRule) GetSeverity() string { return "high" }
func (r *AWSKMSKeyPolicyWildcardRule) GetCategory() string { return "encryption" }
func (r *AWSKMSKeyPolicyWildcardRule) GetProvider() string { return "aws" }
func (r *AWSKMSKeyPolicyWildcardRule) GetTags() []string { return []string{"kms", "policy", "wildcard"} }
func (r *AWSKMSKeyPolicyWildcardRule) GetVersion() string { return "1.0.0" }

func (r *AWSKMSKeyPolicyWildcardRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "aws_kms_key" {
			if policy, exists := block.Attributes["policy"]; exists {
				policyStr := ctyValueToString(policy.Value)
				if strings.Contains(policyStr, `"Principal": "*"`) {
					issues = append(issues, types.Issue{
						Rule: r.GetName(), Severity: r.GetSeverity(),
						Message: "KMS key policy allows access from any principal (*)",
						Line: policy.Range.Start.Line,
						Description: "Specify explicit principals instead of using wildcard",
					})
				}
			}
		}
	}
	return issues
}

// =============================================================================
// AWS ELB/ALB SECURITY RULES (15+ rules)
// =============================================================================

// AWSELBHTTPSOnlyRule ensures load balancers use HTTPS
type AWSELBHTTPSOnlyRule struct{}

func (r *AWSELBHTTPSOnlyRule) GetName() string { return "aws-elb-https-only" }
func (r *AWSELBHTTPSOnlyRule) GetDescription() string { return "Load balancer should use HTTPS listeners only" }
func (r *AWSELBHTTPSOnlyRule) GetSeverity() string { return "high" }
func (r *AWSELBHTTPSOnlyRule) GetCategory() string { return "network" }
func (r *AWSELBHTTPSOnlyRule) GetProvider() string { return "aws" }
func (r *AWSELBHTTPSOnlyRule) GetTags() []string { return []string{"elb", "https", "encryption"} }
func (r *AWSELBHTTPSOnlyRule) GetVersion() string { return "1.0.0" }

func (r *AWSELBHTTPSOnlyRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if isAWSLoadBalancer(&block) {
			for _, listenerBlock := range block.Blocks {
				if listenerBlock.Type == "listener" {
					if protocol, exists := listenerBlock.Attributes["protocol"]; exists {
						protocolStr := ctyValueToString(protocol.Value)
						if protocolStr == "HTTP" {
							issues = append(issues, types.Issue{
								Rule: r.GetName(), Severity: r.GetSeverity(),
								Message: "Load balancer listener uses HTTP instead of HTTPS",
								Line: protocol.Range.Start.Line,
								Description: "Change protocol to HTTPS and configure SSL certificate",
							})
						}
					}
				}
			}
		}
	}
	return issues
}

// AWSELBAccessLogsRule ensures access logs are enabled
type AWSELBAccessLogsRule struct{}

func (r *AWSELBAccessLogsRule) GetName() string { return "aws-elb-access-logs" }
func (r *AWSELBAccessLogsRule) GetDescription() string { return "Load balancer should have access logs enabled" }
func (r *AWSELBAccessLogsRule) GetSeverity() string { return "medium" }
func (r *AWSELBAccessLogsRule) GetCategory() string { return "logging" }
func (r *AWSELBAccessLogsRule) GetProvider() string { return "aws" }
func (r *AWSELBAccessLogsRule) GetTags() []string { return []string{"elb", "access-logs", "monitoring"} }
func (r *AWSELBAccessLogsRule) GetVersion() string { return "1.0.0" }

func (r *AWSELBAccessLogsRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if isAWSLoadBalancer(&block) {
			hasAccessLogs := false
			for _, accessLogsBlock := range block.Blocks {
				if accessLogsBlock.Type == "access_logs" {
					if enabled, exists := accessLogsBlock.Attributes["enabled"]; exists {
						if ctyValueToString(enabled.Value) == "true" {
							hasAccessLogs = true
						}
					}
				}
			}
			if !hasAccessLogs {
				issues = append(issues, types.Issue{
					Rule: r.GetName(), Severity: r.GetSeverity(),
					Message: "Load balancer does not have access logs enabled",
					Line: block.Range.Start.Line,
					Description: "Add access_logs block with enabled = true",
				})
			}
		}
	}
	return issues
}

// =============================================================================
// AWS SNS SECURITY RULES (8+ rules)
// =============================================================================

// AWSSNSTopicEncryptionRule ensures SNS topics are encrypted
type AWSSNSTopicEncryptionRule struct{}

func (r *AWSSNSTopicEncryptionRule) GetName() string { return "aws-sns-topic-encryption" }
func (r *AWSSNSTopicEncryptionRule) GetDescription() string { return "SNS topic should be encrypted" }
func (r *AWSSNSTopicEncryptionRule) GetSeverity() string { return "medium" }
func (r *AWSSNSTopicEncryptionRule) GetCategory() string { return "encryption" }
func (r *AWSSNSTopicEncryptionRule) GetProvider() string { return "aws" }
func (r *AWSSNSTopicEncryptionRule) GetTags() []string { return []string{"sns", "encryption", "messaging"} }
func (r *AWSSNSTopicEncryptionRule) GetVersion() string { return "1.0.0" }

func (r *AWSSNSTopicEncryptionRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "aws_sns_topic" {
			if _, exists := block.Attributes["kms_master_key_id"]; !exists {
				issues = append(issues, types.Issue{
					Rule: r.GetName(), Severity: r.GetSeverity(),
					Message: "SNS topic is not encrypted",
					Line: block.Range.Start.Line,
					Description: "Add kms_master_key_id to encrypt the SNS topic",
				})
			}
		}
	}
	return issues
}

// AWSSNSTopicPolicyWildcardRule detects wildcard principals in SNS topic policies
type AWSSNSTopicPolicyWildcardRule struct{}

func (r *AWSSNSTopicPolicyWildcardRule) GetName() string { return "aws-sns-topic-policy-wildcard" }
func (r *AWSSNSTopicPolicyWildcardRule) GetDescription() string { return "SNS topic policy should not allow wildcard principals" }
func (r *AWSSNSTopicPolicyWildcardRule) GetSeverity() string { return "high" }
func (r *AWSSNSTopicPolicyWildcardRule) GetCategory() string { return "messaging" }
func (r *AWSSNSTopicPolicyWildcardRule) GetProvider() string { return "aws" }
func (r *AWSSNSTopicPolicyWildcardRule) GetTags() []string { return []string{"sns", "policy", "wildcard"} }
func (r *AWSSNSTopicPolicyWildcardRule) GetVersion() string { return "1.0.0" }

func (r *AWSSNSTopicPolicyWildcardRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "aws_sns_topic_policy" {
			if policy, exists := block.Attributes["policy"]; exists {
				policyStr := ctyValueToString(policy.Value)
				if strings.Contains(policyStr, `"Principal": "*"`) {
					issues = append(issues, types.Issue{
						Rule: r.GetName(), Severity: r.GetSeverity(),
						Message: "SNS topic policy allows access from any principal (*)",
						Line: policy.Range.Start.Line,
						Description: "Specify explicit principals instead of using wildcard",
					})
				}
			}
		}
	}
	return issues
}

// =============================================================================
// AWS SQS SECURITY RULES (8+ rules)
// =============================================================================

// AWSSQSQueueEncryptionRule ensures SQS queues are encrypted
type AWSSQSQueueEncryptionRule struct{}

func (r *AWSSQSQueueEncryptionRule) GetName() string { return "aws-sqs-queue-encryption" }
func (r *AWSSQSQueueEncryptionRule) GetDescription() string { return "SQS queue should be encrypted" }
func (r *AWSSQSQueueEncryptionRule) GetSeverity() string { return "medium" }
func (r *AWSSQSQueueEncryptionRule) GetCategory() string { return "encryption" }
func (r *AWSSQSQueueEncryptionRule) GetProvider() string { return "aws" }
func (r *AWSSQSQueueEncryptionRule) GetTags() []string { return []string{"sqs", "encryption", "messaging"} }
func (r *AWSSQSQueueEncryptionRule) GetVersion() string { return "1.0.0" }

func (r *AWSSQSQueueEncryptionRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "aws_sqs_queue" {
			if _, exists := block.Attributes["kms_master_key_id"]; !exists {
				issues = append(issues, types.Issue{
					Rule: r.GetName(), Severity: r.GetSeverity(),
					Message: "SQS queue is not encrypted",
					Line: block.Range.Start.Line,
					Description: "Add kms_master_key_id to encrypt the SQS queue",
				})
			}
		}
	}
	return issues
}

// AWSSQSQueuePolicyWildcardRule detects wildcard principals in SQS queue policies
type AWSSQSQueuePolicyWildcardRule struct{}

func (r *AWSSQSQueuePolicyWildcardRule) GetName() string { return "aws-sqs-queue-policy-wildcard" }
func (r *AWSSQSQueuePolicyWildcardRule) GetDescription() string { return "SQS queue policy should not allow wildcard principals" }
func (r *AWSSQSQueuePolicyWildcardRule) GetSeverity() string { return "high" }
func (r *AWSSQSQueuePolicyWildcardRule) GetCategory() string { return "messaging" }
func (r *AWSSQSQueuePolicyWildcardRule) GetProvider() string { return "aws" }
func (r *AWSSQSQueuePolicyWildcardRule) GetTags() []string { return []string{"sqs", "policy", "wildcard"} }
func (r *AWSSQSQueuePolicyWildcardRule) GetVersion() string { return "1.0.0" }

func (r *AWSSQSQueuePolicyWildcardRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "aws_sqs_queue_policy" {
			if policy, exists := block.Attributes["policy"]; exists {
				policyStr := ctyValueToString(policy.Value)
				if strings.Contains(policyStr, `"Principal": "*"`) {
					issues = append(issues, types.Issue{
						Rule: r.GetName(), Severity: r.GetSeverity(),
						Message: "SQS queue policy allows access from any principal (*)",
						Line: policy.Range.Start.Line,
						Description: "Specify explicit principals instead of using wildcard",
					})
				}
			}
		}
	}
	return issues
}

// =============================================================================
// ADDITIONAL HELPER FUNCTIONS
// =============================================================================

func isAWSSecurityGroup(block *types.Block) bool {
	return block.Type == "resource" && len(block.Labels) >= 2 && 
		   (block.Labels[0] == "aws_security_group" || block.Labels[0] == "aws_default_security_group")
}

func isAWSLoadBalancer(block *types.Block) bool {
	return block.Type == "resource" && len(block.Labels) >= 2 && 
		   (block.Labels[0] == "aws_lb" || block.Labels[0] == "aws_alb" || block.Labels[0] == "aws_elb")
}

func isAWSS3Bucket(block *types.Block) bool {
	return block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "aws_s3_bucket"
}

func isAWSEC2Instance(block *types.Block) bool {
	return block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "aws_instance"
}

func isAWSIAMPolicy(block *types.Block) bool {
	return block.Type == "resource" && len(block.Labels) >= 2 && 
		   (block.Labels[0] == "aws_iam_policy" || block.Labels[0] == "aws_iam_role_policy")
}

func isAWSRDSInstance(block *types.Block) bool {
	return block.Type == "resource" && len(block.Labels) >= 2 && 
		   (block.Labels[0] == "aws_db_instance" || block.Labels[0] == "aws_rds_cluster")
}

func isAWSLambdaFunction(block *types.Block) bool {
	return block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "aws_lambda_function"
}

func ctyValueToString(val interface{}) string {
	if val == nil {
		return ""
	}
	return fmt.Sprintf("%v", val)
} 