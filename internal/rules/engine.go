package rules

import (
	"strings"

	"github.com/heyimusa/go-terraform-linter/internal/parser"
	"github.com/heyimusa/go-terraform-linter/internal/rules/security"
	"github.com/heyimusa/go-terraform-linter/internal/types"
)

// RuleEngine manages and runs all security rules
type RuleEngine struct {
	rules []Rule
}

// NewRuleEngine creates a new rule engine with all built-in rules
func NewRuleEngine() *RuleEngine {
	engine := &RuleEngine{}
	engine.registerRules()
	return engine
}

// RunRules executes all rules against the given configuration
func (re *RuleEngine) RunRules(config *parser.Config, minSeverity string) []types.Issue {
	var allIssues []types.Issue

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

// shouldIncludeIssue determines if an issue should be included based on severity
func (re *RuleEngine) shouldIncludeIssue(issueSeverity, minSeverity string) bool {
	if minSeverity == "all" {
		return true
	}

	severityOrder := map[string]int{
		"low":      1,
		"medium":   2,
		"high":     3,
		"critical": 4,
	}

	issueLevel := severityOrder[strings.ToLower(issueSeverity)]
	minLevel := severityOrder[strings.ToLower(minSeverity)]

	return issueLevel >= minLevel
}

// registerRules registers all built-in security rules
func (re *RuleEngine) registerRules() {
	re.rules = []Rule{
		// Network Security Rules
		&security.PublicAccessRule{},
		&security.OpenPortsRule{},
		&security.UnrestrictedIngressRule{},

		// Storage Security Rules
		&security.UnencryptedStorageRule{},
		&security.EncryptionComplianceRule{},

		// Authentication & Authorization Rules
		&security.WeakPasswordRule{},
		&security.ExposedSecretsRule{},
		&security.IamLeastPrivilegeRule{},
		&security.ExcessivePermissionsRule{},

		// Best Practices Rules
		&security.MissingTagsRule{},
		&security.DeprecatedResourcesRule{},
		&security.MissingBackupRule{},
		&security.WeakCryptoRule{},

		// Cost Optimization Rules
		&security.CostOptimizationRule{},
	}
}

// AddCustomRule adds a custom rule to the engine
func (re *RuleEngine) AddCustomRule(rule Rule) {
	re.rules = append(re.rules, rule)
} 