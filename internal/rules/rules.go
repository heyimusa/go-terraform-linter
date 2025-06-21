package rules

import (
	"strings"

	"github.com/heyimusa/go-terraform-linter/internal/parser"
)

type Issue struct {
	Rule        string
	Message     string
	Description string
	Severity    string
	Line        int
}

type RuleEngine struct {
	rules []Rule
}

type Rule interface {
	Check(config *parser.Config) []Issue
	GetName() string
}

func NewRuleEngine() *RuleEngine {
	engine := &RuleEngine{}
	engine.registerRules()
	return engine
}

func (re *RuleEngine) registerRules() {
	re.rules = []Rule{
		&PublicAccessRule{},
		&UnencryptedStorageRule{},
		&WeakPasswordRule{},
		&MissingTagsRule{},
		&ExposedSecretsRule{},
		&UnrestrictedIngressRule{},
		&DeprecatedResourcesRule{},
		&MissingBackupRule{},
		&WeakCryptoRule{},
		&ExcessivePermissionsRule{},
	}
}

func (re *RuleEngine) RunRules(config *parser.Config, minSeverity string) []Issue {
	var allIssues []Issue

	for _, rule := range re.rules {
		issues := rule.Check(config)
		for _, issue := range issues {
			if re.shouldIncludeIssue(issue.Severity, minSeverity) {
				allIssues = append(allIssues, issue)
			}
		}
	}

	return allIssues
}

func (re *RuleEngine) shouldIncludeIssue(issueSeverity, minSeverity string) bool {
	severityLevels := map[string]int{
		"low":      1,
		"medium":   2,
		"high":     3,
		"critical": 4,
	}

	if minSeverity == "all" {
		return true
	}

	issueLevel := severityLevels[strings.ToLower(issueSeverity)]
	minLevel := severityLevels[strings.ToLower(minSeverity)]

	return issueLevel >= minLevel
}

// Security Rules Implementation

type PublicAccessRule struct{}

func (r *PublicAccessRule) GetName() string { return "PUBLIC_ACCESS" }

func (r *PublicAccessRule) Check(config *parser.Config) []Issue {
	var issues []Issue

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) > 0 {
			resourceType := block.Labels[0]
			
			// Check for public access in various resources
			if strings.Contains(resourceType, "aws_s3_bucket") {
				if attr, exists := block.Attributes["acl"]; exists {
					if acl, ok := attr.Value.(string); ok && acl == "public-read" {
						issues = append(issues, Issue{
							Rule:        r.GetName(),
							Message:     "S3 bucket has public read access",
							Description: "Public read access allows anyone to read bucket contents",
							Severity:    "high",
							Line:        attr.Range.Start.Line,
						})
					}
				}
			}

			if strings.Contains(resourceType, "aws_security_group") {
				for _, nestedBlock := range block.Blocks {
					if nestedBlock.Type == "ingress" {
						if cidr, exists := nestedBlock.Attributes["cidr_blocks"]; exists {
							if cidrStr, ok := cidr.Value.(string); ok && cidrStr == "0.0.0.0/0" {
								issues = append(issues, Issue{
									Rule:        r.GetName(),
									Message:     "Security group allows access from anywhere",
									Description: "0.0.0.0/0 allows access from any IP address",
									Severity:    "high",
									Line:        cidr.Range.Start.Line,
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

type UnencryptedStorageRule struct{}

func (r *UnencryptedStorageRule) GetName() string { return "UNENCRYPTED_STORAGE" }

func (r *UnencryptedStorageRule) Check(config *parser.Config) []Issue {
	var issues []Issue

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) > 0 {
			resourceType := block.Labels[0]
			
			if strings.Contains(resourceType, "aws_ebs_volume") {
				if encrypted, exists := block.Attributes["encrypted"]; exists {
					if enc, ok := encrypted.Value.(bool); ok && !enc {
						issues = append(issues, Issue{
							Rule:        r.GetName(),
							Message:     "EBS volume is not encrypted",
							Description: "Unencrypted EBS volumes can expose sensitive data",
							Severity:    "high",
							Line:        encrypted.Range.Start.Line,
						})
					}
				} else {
					// No encrypted attribute means unencrypted by default
					issues = append(issues, Issue{
						Rule:        r.GetName(),
						Message:     "EBS volume encryption not specified",
						Description: "EBS volumes should be encrypted by default",
						Severity:    "medium",
						Line:        block.Range.Start.Line,
					})
				}
			}
		}
	}

	return issues
}

type WeakPasswordRule struct{}

func (r *WeakPasswordRule) GetName() string { return "WEAK_PASSWORD" }

func (r *WeakPasswordRule) Check(config *parser.Config) []Issue {
	var issues []Issue

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) > 0 {
			resourceType := block.Labels[0]
			
			if strings.Contains(resourceType, "aws_db_instance") {
				if password, exists := block.Attributes["password"]; exists {
					if pwd, ok := password.Value.(string); ok && len(pwd) < 8 {
						issues = append(issues, Issue{
							Rule:        r.GetName(),
							Message:     "Database password is too short",
							Description: "Database passwords should be at least 8 characters long",
							Severity:    "medium",
							Line:        password.Range.Start.Line,
						})
					}
				}
			}
		}
	}

	return issues
}

type MissingTagsRule struct{}

func (r *MissingTagsRule) GetName() string { return "MISSING_TAGS" }

func (r *MissingTagsRule) Check(config *parser.Config) []Issue {
	var issues []Issue

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) > 0 {
			if _, exists := block.Attributes["tags"]; !exists {
				issues = append(issues, Issue{
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

type ExposedSecretsRule struct{}

func (r *ExposedSecretsRule) GetName() string { return "EXPOSED_SECRETS" }

func (r *ExposedSecretsRule) Check(config *parser.Config) []Issue {
	var issues []Issue

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) > 0 {
			// Check for hardcoded secrets
			secretAttributes := []string{"password", "secret", "key", "token"}
			for _, attr := range secretAttributes {
				if secret, exists := block.Attributes[attr]; exists {
					if secretStr, ok := secret.Value.(string); ok && len(secretStr) > 0 {
						issues = append(issues, Issue{
							Rule:        r.GetName(),
							Message:     "Hardcoded secret detected",
							Description: "Secrets should be stored in variables or secret management systems",
							Severity:    "critical",
							Line:        secret.Range.Start.Line,
						})
					}
				}
			}
		}
	}

	return issues
}

type UnrestrictedIngressRule struct{}

func (r *UnrestrictedIngressRule) GetName() string { return "UNRESTRICTED_INGRESS" }

func (r *UnrestrictedIngressRule) Check(config *parser.Config) []Issue {
	var issues []Issue

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) > 0 {
			resourceType := block.Labels[0]
			
			if strings.Contains(resourceType, "aws_security_group") {
				for _, nestedBlock := range block.Blocks {
					if nestedBlock.Type == "ingress" {
						if port, exists := nestedBlock.Attributes["from_port"]; exists {
							if fromPort, ok := port.Value.(int); ok && fromPort == 0 {
								issues = append(issues, Issue{
									Rule:        r.GetName(),
									Message:     "Security group allows all ports",
									Description: "Opening all ports (0) is a security risk",
									Severity:    "high",
									Line:        port.Range.Start.Line,
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

type DeprecatedResourcesRule struct{}

func (r *DeprecatedResourcesRule) GetName() string { return "DEPRECATED_RESOURCES" }

func (r *DeprecatedResourcesRule) Check(config *parser.Config) []Issue {
	var issues []Issue

	deprecatedResources := map[string]string{
		"aws_instance": "Consider using launch templates for better security",
		"aws_elb":      "Use Application Load Balancer (ALB) instead",
	}

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) > 0 {
			resourceType := block.Labels[0]
			
			if reason, deprecated := deprecatedResources[resourceType]; deprecated {
				issues = append(issues, Issue{
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

type MissingBackupRule struct{}

func (r *MissingBackupRule) GetName() string { return "MISSING_BACKUP" }

func (r *MissingBackupRule) Check(config *parser.Config) []Issue {
	var issues []Issue

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) > 0 {
			resourceType := block.Labels[0]
			
			if strings.Contains(resourceType, "aws_rds_cluster") {
				if backup, exists := block.Attributes["backup_retention_period"]; exists {
					if retention, ok := backup.Value.(int); ok && retention == 0 {
						issues = append(issues, Issue{
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

type WeakCryptoRule struct{}

func (r *WeakCryptoRule) GetName() string { return "WEAK_CRYPTO" }

func (r *WeakCryptoRule) Check(config *parser.Config) []Issue {
	var issues []Issue

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) > 0 {
			resourceType := block.Labels[0]
			
			if strings.Contains(resourceType, "aws_cloudfront_distribution") {
				for _, nestedBlock := range block.Blocks {
					if nestedBlock.Type == "viewer_certificate" {
						if minProtocol, exists := nestedBlock.Attributes["minimum_protocol_version"]; exists {
							if protocol, ok := minProtocol.Value.(string); ok && protocol == "TLSv1" {
								issues = append(issues, Issue{
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

type ExcessivePermissionsRule struct{}

func (r *ExcessivePermissionsRule) GetName() string { return "EXCESSIVE_PERMISSIONS" }

func (r *ExcessivePermissionsRule) Check(config *parser.Config) []Issue {
	var issues []Issue

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) > 0 {
			resourceType := block.Labels[0]
			
			if strings.Contains(resourceType, "aws_iam_role") {
				for _, nestedBlock := range block.Blocks {
					if nestedBlock.Type == "inline_policy" {
						if policy, exists := nestedBlock.Attributes["policy"]; exists {
							if policyStr, ok := policy.Value.(string); ok {
								if strings.Contains(policyStr, "\"Effect\": \"Allow\"") && 
								   strings.Contains(policyStr, "\"Action\": \"*\"") {
									issues = append(issues, Issue{
										Rule:        r.GetName(),
										Message:     "IAM role has excessive permissions",
										Description: "Wildcard permissions (*) should be avoided",
										Severity:    "high",
										Line:        policy.Range.Start.Line,
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