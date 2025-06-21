package security

import (
	"strings"

	"github.com/heyimusa/go-terraform-linter/internal/parser"
	"github.com/heyimusa/go-terraform-linter/internal/types"
)

// WeakPasswordRule detects weak password configurations
type WeakPasswordRule struct{}

func (r *WeakPasswordRule) GetName() string { return "WEAK_PASSWORD" }

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