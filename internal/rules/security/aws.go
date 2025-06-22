package security

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/heyimusa/go-terraform-linter/internal/parser"
	"github.com/heyimusa/go-terraform-linter/internal/types"
)

// AWSExposedSecretsRule detects hardcoded AWS credentials and secrets
type AWSExposedSecretsRule struct{}

func (r *AWSExposedSecretsRule) GetName() string {
	return "AWS_EXPOSED_SECRETS"
}
func (r *AWSExposedSecretsRule) GetDescription() string { return "AWS security rule" }
func (r *AWSExposedSecretsRule) GetSeverity() string { return "medium" }
func (r *AWSExposedSecretsRule) GetCategory() string { return "security" }
func (r *AWSExposedSecretsRule) GetProvider() string { return "aws" }
func (r *AWSExposedSecretsRule) GetTags() []string { return []string{"security", "aws", "secrets"} }
func (r *AWSExposedSecretsRule) GetVersion() string { return "1.0.0" }

func (r *AWSExposedSecretsRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	for _, block := range config.Blocks {
		// Check for hardcoded AWS provider credentials
		if block.Type == "provider" && len(block.Labels) > 0 && block.Labels[0] == "aws" {
			for attrName, attr := range block.Attributes {
				if attrName == "access_key" || attrName == "secret_key" || attrName == "token" {
					issues = append(issues, types.Issue{
						Rule:        r.GetName(),
						Severity:    "CRITICAL",
						Message:     fmt.Sprintf("Hardcoded AWS provider credential: %s", attrName),
						Description: "AWS provider credentials should be stored in variables or environment.",
						Line:        attr.Range.Start.Line,
					})
				}
			}
		}

		// Check for hardcoded secrets in variables and resources
		for _, attr := range block.Attributes {
			if attr.RawValue == "" {
				continue
			}

			rawValue := strings.ToLower(attr.RawValue)

			// AWS Access Key patterns
			if matched, _ := regexp.MatchString(`AKIA[0-9A-Z]{16}`, strings.ToUpper(attr.RawValue)); matched {
				issues = append(issues, types.Issue{
					Rule:        r.GetName(),
					Severity:    "CRITICAL",
					Message:     "Hardcoded AWS Access Key detected",
					Description: "AWS Access Keys should not be hardcoded. Use IAM roles or environment variables.",
					Line:        block.Range.Start.Line,
				})
			}

			// AWS Secret Access Key patterns (40 characters base64)
			if matched, _ := regexp.MatchString(`[A-Za-z0-9/+=]{40}`, attr.RawValue); matched && strings.Contains(rawValue, "secret") {
				issues = append(issues, types.Issue{
					Rule:        r.GetName(),
					Severity:    "CRITICAL",
					Message:     "Hardcoded AWS Secret Access Key detected",
					Description: "AWS Secret Access Keys should not be hardcoded. Use IAM roles or environment variables.",
					Line:        block.Range.Start.Line,
				})
			}

			// Database connection strings
			if strings.Contains(rawValue, "://") && strings.Contains(rawValue, "@") && 
			   (strings.Contains(rawValue, "rds") || strings.Contains(rawValue, "mysql") || 
			    strings.Contains(rawValue, "postgres") || strings.Contains(rawValue, "mongodb")) {
				issues = append(issues, types.Issue{
					Rule:        r.GetName(),
					Severity:    "CRITICAL",
					Message:     "Hardcoded database connection string with credentials",
					Description: "Database connection strings should not contain hardcoded credentials.",
					Line:        block.Range.Start.Line,
				})
			}

			// API Keys and tokens
			if strings.Contains(rawValue, "api_key") || strings.Contains(rawValue, "api-key") ||
			   strings.Contains(rawValue, "apikey") || strings.Contains(rawValue, "token") {
				if matched, _ := regexp.MatchString(`[a-zA-Z0-9]{20,}`, attr.RawValue); matched {
					issues = append(issues, types.Issue{
						Rule:        r.GetName(),
						Severity:    "CRITICAL",
						Message:     "Hardcoded API key or token detected",
						Description: "API keys and tokens should not be hardcoded. Use AWS Secrets Manager or Parameter Store.",
						Line:        block.Range.Start.Line,
					})
				}
			}

			// JWT Secrets
			if strings.Contains(rawValue, "jwt") && strings.Contains(rawValue, "secret") {
				issues = append(issues, types.Issue{
					Rule:        r.GetName(),
					Severity:    "CRITICAL",
					Message:     "Hardcoded JWT secret detected",
					Description: "JWT secrets should not be hardcoded. Use AWS Secrets Manager.",
					Line:        block.Range.Start.Line,
				})
			}

			// OAuth secrets
			if strings.Contains(rawValue, "client_secret") || strings.Contains(rawValue, "oauth") {
				issues = append(issues, types.Issue{
					Rule:        r.GetName(),
					Severity:    "CRITICAL",
					Message:     "Hardcoded OAuth client secret detected",
					Description: "OAuth client secrets should not be hardcoded. Use AWS Secrets Manager.",
					Line:        block.Range.Start.Line,
				})
			}

			// Debug mode enabled
			if (strings.Contains(rawValue, "debug") || strings.Contains(rawValue, "app_debug")) && 
			   strings.Contains(rawValue, "true") {
				issues = append(issues, types.Issue{
					Rule:        r.GetName(),
					Severity:    "HIGH",
					Message:     "Debug mode enabled in production",
					Description: "Debug mode should be disabled in production environments.",
					Line:        block.Range.Start.Line,
				})
			}
		}
	}

	return issues
}

// AWSPublicS3BucketRule detects S3 buckets with public access
type AWSPublicS3BucketRule struct{}

func (r *AWSPublicS3BucketRule) GetName() string {
	return "AWS_PUBLIC_S3_BUCKET"
}
func (r *AWSPublicS3BucketRule) GetDescription() string { return "AWS security rule" }
func (r *AWSPublicS3BucketRule) GetSeverity() string { return "medium" }
func (r *AWSPublicS3BucketRule) GetCategory() string { return "storage" }
func (r *AWSPublicS3BucketRule) GetProvider() string { return "aws" }
func (r *AWSPublicS3BucketRule) GetTags() []string { return []string{"security", "aws", "s3", "public-access"} }
func (r *AWSPublicS3BucketRule) GetVersion() string { return "1.0.0" }

func (r *AWSPublicS3BucketRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 {
			resourceType := block.Labels[0]
			
			// Check S3 bucket public access
			if resourceType == "aws_s3_bucket_public_access_block" {
				publicSettings := map[string]bool{
					"block_public_acls":       false,
					"block_public_policy":     false,
					"ignore_public_acls":      false,
					"restrict_public_buckets": false,
				}

				for attrName, attr := range block.Attributes {
					if _, exists := publicSettings[attrName]; exists {
						if strings.Contains(strings.ToLower(attr.RawValue), "false") {
							issues = append(issues, types.Issue{
								Rule:        r.GetName(),
								Severity:    "CRITICAL",
								Message:     fmt.Sprintf("S3 bucket allows public access: %s is false", attrName),
								Description: "S3 buckets should block all public access for security.",
								Line:        attr.Range.Start.Line,
							})
						}
					}
				}
			}

			// Check S3 bucket ACL
			if resourceType == "aws_s3_bucket_acl" {
				if aclAttr, exists := block.Attributes["acl"]; exists {
					if strings.Contains(aclAttr.RawValue, "public-read") || 
					   strings.Contains(aclAttr.RawValue, "public-read-write") {
						issues = append(issues, types.Issue{
							Rule:        r.GetName(),
							Severity:    "CRITICAL",
							Message:     "S3 bucket has public ACL",
							Description: "S3 buckets should not have public read/write ACLs.",
							Line:        aclAttr.Range.Start.Line,
						})
					}
				}
			}
		}
	}

	return issues
}

// AWSUnencryptedStorageRule detects unencrypted storage resources
type AWSUnencryptedStorageRule struct{}

func (r *AWSUnencryptedStorageRule) GetName() string {
	return "AWS_UNENCRYPTED_STORAGE"
}
func (r *AWSUnencryptedStorageRule) GetDescription() string { return "AWS security rule" }
func (r *AWSUnencryptedStorageRule) GetSeverity() string { return "medium" }
func (r *AWSUnencryptedStorageRule) GetCategory() string { return "storage" }
func (r *AWSUnencryptedStorageRule) GetProvider() string { return "aws" }
func (r *AWSUnencryptedStorageRule) GetTags() []string { return []string{"security", "aws", "encryption", "storage"} }
func (r *AWSUnencryptedStorageRule) GetVersion() string { return "1.0.0" }

func (r *AWSUnencryptedStorageRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 {
			resourceType := block.Labels[0]
			
			encryptionRequired := map[string][]string{
				"aws_s3_bucket":                    {"server_side_encryption_configuration"},
				"aws_ebs_volume":                   {"encrypted"},
				"aws_rds_cluster":                  {"storage_encrypted"},
				"aws_rds_instance":                 {"storage_encrypted"},
				"aws_db_instance":                  {"storage_encrypted"},
				"aws_elasticache_replication_group": {"at_rest_encryption_enabled", "transit_encryption_enabled"},
				"aws_redshift_cluster":             {"encrypted"},
				"aws_efs_file_system":              {"encrypted"},
			}

			if requiredAttrs, exists := encryptionRequired[resourceType]; exists {
				for _, requiredAttr := range requiredAttrs {
					if attr, found := block.Attributes[requiredAttr]; found {
						if strings.Contains(strings.ToLower(attr.RawValue), "false") {
							issues = append(issues, types.Issue{
								Rule:        r.GetName(),
								Severity:    "HIGH",
								Message:     fmt.Sprintf("%s has encryption disabled", resourceType),
								Description: "AWS storage resources should be encrypted at rest.",
								Line:        attr.Range.Start.Line,
							})
						}
					} else {
						issues = append(issues, types.Issue{
							Rule:        r.GetName(),
							Severity:    "HIGH",
							Message:     fmt.Sprintf("%s missing encryption configuration", resourceType),
							Description: "AWS storage resources should be encrypted at rest.",
							Line:        block.Range.Start.Line,
						})
					}
				}
			}
		}
	}

	return issues
}

// AWSWeakPasswordsRule detects weak password configurations
type AWSWeakPasswordsRule struct{}

func (r *AWSWeakPasswordsRule) GetName() string {
	return "AWS_WEAK_PASSWORDS"
}
func (r *AWSWeakPasswordsRule) GetDescription() string { return "AWS security rule" }
func (r *AWSWeakPasswordsRule) GetSeverity() string { return "medium" }
func (r *AWSWeakPasswordsRule) GetCategory() string { return "authentication" }
func (r *AWSWeakPasswordsRule) GetProvider() string { return "aws" }
func (r *AWSWeakPasswordsRule) GetTags() []string { return []string{"security", "aws", "authentication", "password"} }
func (r *AWSWeakPasswordsRule) GetVersion() string { return "1.0.0" }

func (r *AWSWeakPasswordsRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 {
			resourceType := block.Labels[0]
			
			// Check database passwords
			if strings.Contains(resourceType, "rds") || strings.Contains(resourceType, "db_instance") {
				if passwordAttr, exists := block.Attributes["password"]; exists {
					if len(passwordAttr.RawValue) < 12 {
						issues = append(issues, types.Issue{
							Rule:        r.GetName(),
							Severity:    "HIGH",
							Message:     "Database password is too short",
							Description: "Database passwords should be at least 12 characters long.",
							Line:        passwordAttr.Range.Start.Line,
						})
					}
					if strings.Contains(passwordAttr.RawValue, "password") || strings.Contains(passwordAttr.RawValue, "123") {
						issues = append(issues, types.Issue{
							Rule:        r.GetName(),
							Severity:    "HIGH",
							Message:     "Database password is weak or predictable",
							Description: "Database passwords should be strong and unpredictable.",
							Line:        passwordAttr.Range.Start.Line,
						})
					}
				}
			}
		}
	}

	return issues
}

// AWSMissingTagsRule detects resources without proper tagging
type AWSMissingTagsRule struct{}

func (r *AWSMissingTagsRule) GetName() string {
	return "AWS_MISSING_TAGS"
}
func (r *AWSMissingTagsRule) GetDescription() string { return "AWS security rule" }
func (r *AWSMissingTagsRule) GetSeverity() string { return "medium" }
func (r *AWSMissingTagsRule) GetCategory() string { return "best-practices" }
func (r *AWSMissingTagsRule) GetProvider() string { return "aws" }
func (r *AWSMissingTagsRule) GetTags() []string { return []string{"best-practices", "aws", "tagging"} }
func (r *AWSMissingTagsRule) GetVersion() string { return "1.0.0" }

func (r *AWSMissingTagsRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 {
			resourceType := block.Labels[0]
			
			// Resources that should be tagged
			taggableResources := []string{
				"aws_instance", "aws_s3_bucket", "aws_rds_instance", "aws_rds_cluster",
				"aws_vpc", "aws_subnet", "aws_security_group", "aws_load_balancer",
				"aws_efs_file_system", "aws_ebs_volume", "aws_lambda_function",
			}

			for _, taggable := range taggableResources {
				if resourceType == taggable {
					if _, hasTagsAttribute := block.Attributes["tags"]; !hasTagsAttribute {
						issues = append(issues, types.Issue{
							Rule:        r.GetName(),
							Severity:    "LOW",
							Message:     "Resource missing tags",
							Description: "AWS resources should be tagged for better organization and cost tracking",
							Line:        block.Range.Start.Line,
						})
					}
					break
				}
			}
		}
	}

	return issues
}

// AWSUnrestrictedIngressRule detects security groups with unrestricted ingress
type AWSUnrestrictedIngressRule struct{}

func (r *AWSUnrestrictedIngressRule) GetName() string {
	return "AWS_UNRESTRICTED_INGRESS"
}
func (r *AWSUnrestrictedIngressRule) GetDescription() string { return "AWS security rule" }
func (r *AWSUnrestrictedIngressRule) GetSeverity() string { return "medium" }
func (r *AWSUnrestrictedIngressRule) GetCategory() string { return "network" }
func (r *AWSUnrestrictedIngressRule) GetProvider() string { return "aws" }
func (r *AWSUnrestrictedIngressRule) GetTags() []string { return []string{"security", "aws", "network", "ingress"} }
func (r *AWSUnrestrictedIngressRule) GetVersion() string { return "1.0.0" }

func (r *AWSUnrestrictedIngressRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 {
			resourceType := block.Labels[0]
			
			if resourceType == "aws_security_group" || resourceType == "aws_security_group_rule" {
				if cidrAttr, exists := block.Attributes["cidr_blocks"]; exists {
					if strings.Contains(cidrAttr.RawValue, "0.0.0.0/0") {
						issues = append(issues, types.Issue{
							Rule:        r.GetName(),
							Severity:    "CRITICAL",
							Message:     "Security group allows unrestricted ingress (0.0.0.0/0)",
							Description: "Security groups should not allow unrestricted access from the internet.",
							Line:        cidrAttr.Range.Start.Line,
						})
					}
				}
			}
		}
	}

	return issues
}

// AWSDeprecatedResourcesRule detects usage of deprecated resources
type AWSDeprecatedResourcesRule struct{}

func (r *AWSDeprecatedResourcesRule) GetName() string {
	return "AWS_DEPRECATED_RESOURCES"
}
func (r *AWSDeprecatedResourcesRule) GetDescription() string { return "AWS security rule" }
func (r *AWSDeprecatedResourcesRule) GetSeverity() string { return "medium" }
func (r *AWSDeprecatedResourcesRule) GetCategory() string { return "best-practices" }
func (r *AWSDeprecatedResourcesRule) GetProvider() string { return "aws" }
func (r *AWSDeprecatedResourcesRule) GetTags() []string { return []string{"best-practices", "aws", "deprecated"} }
func (r *AWSDeprecatedResourcesRule) GetVersion() string { return "1.0.0" }

func (r *AWSDeprecatedResourcesRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 {
			resourceType := block.Labels[0]
			
			deprecatedResources := map[string]string{
				"aws_db_security_group":     "Use aws_security_group instead",
				"aws_elasticache_security_group": "Use aws_security_group instead",
				"aws_redshift_security_group": "Use aws_security_group instead",
			}

			if replacement, exists := deprecatedResources[resourceType]; exists {
				issues = append(issues, types.Issue{
					Rule:        r.GetName(),
					Severity:    "MEDIUM",
					Message:     fmt.Sprintf("Using deprecated resource: %s", resourceType),
					Description: replacement,
					Line:        block.Range.Start.Line,
				})
			}
		}
	}

	return issues
}

// AWSMissingBackupRule detects resources without backup configuration
type AWSMissingBackupRule struct{}

func (r *AWSMissingBackupRule) GetName() string {
	return "AWS_MISSING_BACKUP"
}
func (r *AWSMissingBackupRule) GetDescription() string { return "AWS security rule" }
func (r *AWSMissingBackupRule) GetSeverity() string { return "medium" }
func (r *AWSMissingBackupRule) GetCategory() string { return "reliability" }
func (r *AWSMissingBackupRule) GetProvider() string { return "aws" }
func (r *AWSMissingBackupRule) GetTags() []string { return []string{"reliability", "aws", "backup"} }
func (r *AWSMissingBackupRule) GetVersion() string { return "1.0.0" }

func (r *AWSMissingBackupRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 {
			resourceType := block.Labels[0]
			
			backupRequired := map[string]string{
				"aws_rds_instance": "backup_retention_period",
				"aws_rds_cluster":  "backup_retention_period",
				"aws_efs_file_system": "backup_policy",
			}

			if backupAttr, exists := backupRequired[resourceType]; exists {
				if attr, found := block.Attributes[backupAttr]; found {
					if strings.Contains(attr.RawValue, "0") || strings.Contains(strings.ToLower(attr.RawValue), "disabled") {
						issues = append(issues, types.Issue{
							Rule:        r.GetName(),
							Severity:    "MEDIUM",
							Message:     fmt.Sprintf("%s has backup disabled", resourceType),
							Description: "Critical resources should have backup enabled.",
							Line:        attr.Range.Start.Line,
						})
					}
				} else if resourceType != "aws_efs_file_system" {
					issues = append(issues, types.Issue{
						Rule:        r.GetName(),
						Severity:    "MEDIUM",
						Message:     fmt.Sprintf("%s missing backup configuration", resourceType),
						Description: "Critical resources should have backup enabled.",
						Line:        block.Range.Start.Line,
					})
				}
			}
		}
	}

	return issues
}

// AWSWeakCryptoRule detects weak cryptographic configurations
type AWSWeakCryptoRule struct{}

func (r *AWSWeakCryptoRule) GetName() string {
	return "AWS_WEAK_CRYPTO"
}
func (r *AWSWeakCryptoRule) GetDescription() string { return "AWS security rule" }
func (r *AWSWeakCryptoRule) GetSeverity() string { return "medium" }
func (r *AWSWeakCryptoRule) GetCategory() string { return "security" }
func (r *AWSWeakCryptoRule) GetProvider() string { return "aws" }
func (r *AWSWeakCryptoRule) GetTags() []string { return []string{"security", "aws", "cryptography"} }
func (r *AWSWeakCryptoRule) GetVersion() string { return "1.0.0" }

func (r *AWSWeakCryptoRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 {
			resourceType := block.Labels[0]
			
			// Check for weak SSL/TLS policies
			if resourceType == "aws_lb_listener" || resourceType == "aws_alb_listener" {
				if sslAttr, exists := block.Attributes["ssl_policy"]; exists {
					weakPolicies := []string{"ELBSecurityPolicy-2016-08", "ELBSecurityPolicy-TLS-1-0-2015-04"}
					for _, weak := range weakPolicies {
						if strings.Contains(sslAttr.RawValue, weak) {
							issues = append(issues, types.Issue{
								Rule:        r.GetName(),
								Severity:    "HIGH",
								Message:     "Load balancer using weak SSL/TLS policy",
								Description: "Use modern SSL/TLS policies for better security.",
								Line:        sslAttr.Range.Start.Line,
							})
							break
						}
					}
				}
			}
		}
	}

	return issues
}

// AWSExcessivePermissionsRule detects IAM policies with excessive permissions
type AWSExcessivePermissionsRule struct{}

func (r *AWSExcessivePermissionsRule) GetName() string {
	return "AWS_EXCESSIVE_PERMISSIONS"
}
func (r *AWSExcessivePermissionsRule) GetDescription() string { return "AWS security rule" }
func (r *AWSExcessivePermissionsRule) GetSeverity() string { return "medium" }
func (r *AWSExcessivePermissionsRule) GetCategory() string { return "iam" }
func (r *AWSExcessivePermissionsRule) GetProvider() string { return "aws" }
func (r *AWSExcessivePermissionsRule) GetTags() []string { return []string{"security", "aws", "iam", "permissions"} }
func (r *AWSExcessivePermissionsRule) GetVersion() string { return "1.0.0" }

func (r *AWSExcessivePermissionsRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 {
			resourceType := block.Labels[0]
			
			if resourceType == "aws_iam_policy" || resourceType == "aws_iam_role_policy" {
				if policyAttr, exists := block.Attributes["policy"]; exists {
					if strings.Contains(policyAttr.RawValue, "*") && strings.Contains(policyAttr.RawValue, "Action") {
						issues = append(issues, types.Issue{
							Rule:        r.GetName(),
							Severity:    "HIGH",
							Message:     "IAM policy with wildcard (*) permissions",
							Description: "IAM policies should follow the principle of least privilege.",
							Line:        policyAttr.Range.Start.Line,
						})
					}
				}
			}
		}
	}

	return issues
}

// AWSOpenPortsRule detects security groups with open dangerous ports
type AWSOpenPortsRule struct{}

func (r *AWSOpenPortsRule) GetName() string {
	return "AWS_OPEN_PORTS"
}
func (r *AWSOpenPortsRule) GetDescription() string { return "AWS security rule" }
func (r *AWSOpenPortsRule) GetSeverity() string { return "medium" }
func (r *AWSOpenPortsRule) GetCategory() string { return "network" }
func (r *AWSOpenPortsRule) GetProvider() string { return "aws" }
func (r *AWSOpenPortsRule) GetTags() []string { return []string{"security", "aws", "network", "ports"} }
func (r *AWSOpenPortsRule) GetVersion() string { return "1.0.0" }

func (r *AWSOpenPortsRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 {
			resourceType := block.Labels[0]
			
			if resourceType == "aws_security_group_rule" {
				dangerousPorts := []string{"22", "3389", "1433", "3306", "5432", "6379", "27017"}
				
				for _, portAttr := range []string{"from_port", "to_port"} {
					if attr, exists := block.Attributes[portAttr]; exists {
						for _, port := range dangerousPorts {
							if strings.Contains(attr.RawValue, port) {
								issues = append(issues, types.Issue{
									Rule:        r.GetName(),
									Severity:    "MEDIUM",
									Message:     fmt.Sprintf("Potentially dangerous port %s is open", port),
									Description: "Sensitive ports should be restricted to specific IP ranges.",
									Line:        attr.Range.Start.Line,
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

// AWSEncryptionComplianceRule detects encryption compliance issues
type AWSEncryptionComplianceRule struct{}

func (r *AWSEncryptionComplianceRule) GetName() string {
	return "AWS_ENCRYPTION_COMPLIANCE"
}
func (r *AWSEncryptionComplianceRule) GetDescription() string { return "AWS security rule" }
func (r *AWSEncryptionComplianceRule) GetSeverity() string { return "medium" }
func (r *AWSEncryptionComplianceRule) GetCategory() string { return "compliance" }
func (r *AWSEncryptionComplianceRule) GetProvider() string { return "aws" }
func (r *AWSEncryptionComplianceRule) GetTags() []string { return []string{"security", "aws", "compliance", "encryption"} }
func (r *AWSEncryptionComplianceRule) GetVersion() string { return "1.0.0" }

func (r *AWSEncryptionComplianceRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 {
			resourceType := block.Labels[0]
			
			// Check for encryption in transit
			if resourceType == "aws_elasticache_replication_group" {
				if transitAttr, exists := block.Attributes["transit_encryption_enabled"]; exists {
					if strings.Contains(strings.ToLower(transitAttr.RawValue), "false") {
						issues = append(issues, types.Issue{
							Rule:        r.GetName(),
							Severity:    "HIGH",
							Message:     "ElastiCache encryption in transit is disabled",
							Description: "ElastiCache should have encryption in transit enabled.",
							Line:        transitAttr.Range.Start.Line,
						})
					}
				} else {
					issues = append(issues, types.Issue{
						Rule:        r.GetName(),
						Severity:    "HIGH",
						Message:     "ElastiCache missing encryption in transit configuration",
						Description: "ElastiCache should have encryption in transit enabled.",
						Line:        block.Range.Start.Line,
					})
				}
			}
		}
	}

	return issues
}

// AWSCostOptimizationRule detects cost optimization issues
type AWSCostOptimizationRule struct{}

func (r *AWSCostOptimizationRule) GetName() string {
	return "AWS_COST_OPTIMIZATION"
}
func (r *AWSCostOptimizationRule) GetDescription() string { return "AWS security rule" }
func (r *AWSCostOptimizationRule) GetSeverity() string { return "medium" }
func (r *AWSCostOptimizationRule) GetCategory() string { return "cost" }
func (r *AWSCostOptimizationRule) GetProvider() string { return "aws" }
func (r *AWSCostOptimizationRule) GetTags() []string { return []string{"cost", "aws", "optimization"} }
func (r *AWSCostOptimizationRule) GetVersion() string { return "1.0.0" }

func (r *AWSCostOptimizationRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 {
			resourceType := block.Labels[0]
			
			// Check for expensive instance types
			if resourceType == "aws_instance" {
				if instanceAttr, exists := block.Attributes["instance_type"]; exists {
					expensiveTypes := []string{"m5.24xlarge", "c5.24xlarge", "r5.24xlarge", "x1e.32xlarge"}
					for _, expensive := range expensiveTypes {
						if strings.Contains(instanceAttr.RawValue, expensive) {
							issues = append(issues, types.Issue{
								Rule:        r.GetName(),
								Severity:    "LOW",
								Message:     "Using expensive instance type",
								Description: "Consider using smaller instance types or reserved instances for cost optimization.",
								Line:        instanceAttr.Range.Start.Line,
							})
							break
						}
					}
				}
			}
		}
	}

	return issues
} 