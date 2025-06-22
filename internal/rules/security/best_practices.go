package security

import (
	"strings"

	"github.com/heyimusa/go-terraform-linter/internal/parser"
	"github.com/heyimusa/go-terraform-linter/internal/types"
)

// MissingTagsRule detects resources without proper tagging
type MissingTagsRule struct{}

func (r *MissingTagsRule) GetName() string { return "MISSING_TAGS" }
func (r *MissingTagsRule) GetDescription() string { return "Detects resources without proper tagging" }
func (r *MissingTagsRule) GetSeverity() string { return "low" }
func (r *MissingTagsRule) GetCategory() string { return "best-practices" }
func (r *MissingTagsRule) GetProvider() string { return "multi" }
func (r *MissingTagsRule) GetTags() []string { return []string{"best-practices", "tagging", "organization"} }
func (r *MissingTagsRule) GetVersion() string { return "1.0.0" }

func (r *MissingTagsRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) > 0 {
			if _, exists := block.Attributes["tags"]; !exists {
				issues = append(issues, types.Issue{
					Rule:        r.GetName(),
					Message:     "Resource missing tags",
					Description: "Resources should be tagged for better organization and cost tracking",
					Severity:    "low",
					Line:        block.Range.Start.Line,
				})
			}
		}
	}

	return issues
}

// DeprecatedResourcesRule detects usage of deprecated Terraform resources
type DeprecatedResourcesRule struct{}

func (r *DeprecatedResourcesRule) GetName() string { return "DEPRECATED_RESOURCES" }
func (r *DeprecatedResourcesRule) GetDescription() string { return "Detects usage of deprecated Terraform resources" }
func (r *DeprecatedResourcesRule) GetSeverity() string { return "medium" }
func (r *DeprecatedResourcesRule) GetCategory() string { return "best-practices" }
func (r *DeprecatedResourcesRule) GetProvider() string { return "aws" }
func (r *DeprecatedResourcesRule) GetTags() []string { return []string{"best-practices", "deprecated", "modernization"} }
func (r *DeprecatedResourcesRule) GetVersion() string { return "1.0.0" }

func (r *DeprecatedResourcesRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	deprecatedResources := map[string]string{
		"aws_instance": "Consider using launch templates for better security",
		"aws_elb":      "Use Application Load Balancer (ALB) instead",
	}

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) > 0 {
			resourceType := block.Labels[0]
			
			if reason, deprecated := deprecatedResources[resourceType]; deprecated {
				issues = append(issues, types.Issue{
					Rule:        r.GetName(),
					Message:     "Deprecated resource type used",
					Description: reason,
					Severity:    "medium",
					Line:        block.Range.Start.Line,
				})
			}
		}
	}

	return issues
}

// MissingBackupRule detects resources without backup configurations
type MissingBackupRule struct{}

func (r *MissingBackupRule) GetName() string { return "MISSING_BACKUP" }
func (r *MissingBackupRule) GetDescription() string { return "Detects resources without backup configurations" }
func (r *MissingBackupRule) GetSeverity() string { return "high" }
func (r *MissingBackupRule) GetCategory() string { return "reliability" }
func (r *MissingBackupRule) GetProvider() string { return "aws" }
func (r *MissingBackupRule) GetTags() []string { return []string{"reliability", "backup", "data-protection"} }
func (r *MissingBackupRule) GetVersion() string { return "1.0.0" }

func (r *MissingBackupRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) > 0 {
			resourceType := block.Labels[0]
			
			if strings.Contains(resourceType, "aws_rds_cluster") {
				if backup, exists := block.Attributes["backup_retention_period"]; exists {
					if retention, ok := backup.Value.(int); ok && retention == 0 {
						issues = append(issues, types.Issue{
							Rule:        r.GetName(),
							Message:     "RDS cluster has no backup retention",
							Description: "Backup retention should be enabled for data protection",
							Severity:    "high",
							Line:        backup.Range.Start.Line,
						})
					}
				}
			}
		}
	}

	return issues
}

// WeakCryptoRule detects weak cryptographic configurations
type WeakCryptoRule struct{}

func (r *WeakCryptoRule) GetName() string { return "WEAK_CRYPTO" }
func (r *WeakCryptoRule) GetDescription() string { return "Detects weak cryptographic configurations" }
func (r *WeakCryptoRule) GetSeverity() string { return "medium" }
func (r *WeakCryptoRule) GetCategory() string { return "security" }
func (r *WeakCryptoRule) GetProvider() string { return "aws" }
func (r *WeakCryptoRule) GetTags() []string { return []string{"security", "cryptography", "tls"} }
func (r *WeakCryptoRule) GetVersion() string { return "1.0.0" }

func (r *WeakCryptoRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) > 0 {
			resourceType := block.Labels[0]
			
			if strings.Contains(resourceType, "aws_cloudfront_distribution") {
				for _, nestedBlock := range block.Blocks {
					if nestedBlock.Type == "viewer_certificate" {
						if minProtocol, exists := nestedBlock.Attributes["minimum_protocol_version"]; exists {
							if protocol, ok := minProtocol.Value.(string); ok && protocol == "TLSv1" {
								issues = append(issues, types.Issue{
									Rule:        r.GetName(),
									Message:     "Weak TLS protocol version",
									Description: "TLSv1 is deprecated, use TLSv1.2 or higher",
									Severity:    "medium",
									Line:        minProtocol.Range.Start.Line,
								})
							}
						}
					}
				}
			}
		}
	}

	return issues
} 