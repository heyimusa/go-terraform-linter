package security

import (
	"strings"

	"github.com/heyimusa/go-terraform-linter/internal/parser"
	"github.com/heyimusa/go-terraform-linter/internal/types"
)

// WeakPasswordRule detects weak password configurations
type WeakPasswordRule struct{}

func (r *WeakPasswordRule) GetName() string { return "WEAK_PASSWORD" }
func (r *WeakPasswordRule) GetDescription() string { return "Detects weak password configurations" }
func (r *WeakPasswordRule) GetSeverity() string { return "medium" }
func (r *WeakPasswordRule) GetCategory() string { return "authentication" }
func (r *WeakPasswordRule) GetProvider() string { return "aws" }
func (r *WeakPasswordRule) GetTags() []string { return []string{"security", "authentication", "password"} }
func (r *WeakPasswordRule) GetVersion() string { return "1.0.0" }

func (r *WeakPasswordRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) > 0 {
			resourceType := block.Labels[0]
			
			if strings.Contains(resourceType, "aws_db_instance") {
				if password, exists := block.Attributes["password"]; exists {
					if pwd, ok := password.Value.(string); ok && len(pwd) < 8 {
						issues = append(issues, types.Issue{
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

// ExposedSecretsRule detects hardcoded secrets
type ExposedSecretsRule struct{}

func (r *ExposedSecretsRule) GetName() string { return "EXPOSED_SECRETS" }
func (r *ExposedSecretsRule) GetDescription() string { return "Detects hardcoded secrets" }
func (r *ExposedSecretsRule) GetSeverity() string { return "critical" }
func (r *ExposedSecretsRule) GetCategory() string { return "security" }
func (r *ExposedSecretsRule) GetProvider() string { return "multi" }
func (r *ExposedSecretsRule) GetTags() []string { return []string{"security", "secrets", "hardcoded"} }
func (r *ExposedSecretsRule) GetVersion() string { return "1.0.0" }

func (r *ExposedSecretsRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) > 0 {
			// Check for hardcoded secrets
			secretAttributes := []string{"password", "secret", "key", "token"}
			for _, attr := range secretAttributes {
				if secret, exists := block.Attributes[attr]; exists {
					if secretStr, ok := secret.Value.(string); ok && len(secretStr) > 0 {
						issues = append(issues, types.Issue{
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

// IamLeastPrivilegeRule detects IAM policies with excessive permissions
type IamLeastPrivilegeRule struct{}

func (r *IamLeastPrivilegeRule) GetName() string { return "IAM_LEAST_PRIVILEGE" }
func (r *IamLeastPrivilegeRule) GetDescription() string { return "Detects IAM policies with excessive permissions" }
func (r *IamLeastPrivilegeRule) GetSeverity() string { return "high" }
func (r *IamLeastPrivilegeRule) GetCategory() string { return "iam" }
func (r *IamLeastPrivilegeRule) GetProvider() string { return "aws" }
func (r *IamLeastPrivilegeRule) GetTags() []string { return []string{"security", "iam", "permissions"} }
func (r *IamLeastPrivilegeRule) GetVersion() string { return "1.0.0" }

func (r *IamLeastPrivilegeRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) > 0 &&
			strings.Contains(block.Labels[0], "iam_role") {
			for _, nested := range block.Blocks {
				if nested.Type == "inline_policy" {
					if policy, exists := nested.Attributes["policy"]; exists {
						if policyStr, ok := policy.Value.(string); ok {
							if strings.Contains(policyStr, "\"Action\": \"*\"") &&
								strings.Contains(policyStr, "\"Effect\": \"Allow\"") {
								issues = append(issues, types.Issue{
									Rule:        r.GetName(),
									Message:     "IAM policy allows all actions (*)",
									Description: "Use least privilege principle. Avoid wildcard actions.",
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
	return issues
}

// ExcessivePermissionsRule detects IAM roles with excessive permissions
type ExcessivePermissionsRule struct{}

func (r *ExcessivePermissionsRule) GetName() string { return "EXCESSIVE_PERMISSIONS" }
func (r *ExcessivePermissionsRule) GetDescription() string { return "Detects IAM roles with excessive permissions" }
func (r *ExcessivePermissionsRule) GetSeverity() string { return "high" }
func (r *ExcessivePermissionsRule) GetCategory() string { return "iam" }
func (r *ExcessivePermissionsRule) GetProvider() string { return "aws" }
func (r *ExcessivePermissionsRule) GetTags() []string { return []string{"security", "iam", "excessive-permissions"} }
func (r *ExcessivePermissionsRule) GetVersion() string { return "1.0.0" }

func (r *ExcessivePermissionsRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

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
									issues = append(issues, types.Issue{
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