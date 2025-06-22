package rules

import (
	"strings"

	"github.com/heyimusa/go-terraform-linter/internal/parser"
	"github.com/heyimusa/go-terraform-linter/internal/rules/security"
	"github.com/heyimusa/go-terraform-linter/internal/types"
)

// RuleEngine manages and runs all security rules
type RuleEngine struct {
	rules    []Rule
	registry *DefaultRuleRegistry
}

// NewRuleEngine creates a new rule engine with all built-in rules
func NewRuleEngine() *RuleEngine {
	engine := &RuleEngine{
		registry: NewRuleRegistry(),
	}
	engine.registerRules()
	return engine
}

// NewRuleEngineWithRegistry creates a new rule engine with custom registry
func NewRuleEngineWithRegistry(registry *DefaultRuleRegistry) *RuleEngine {
	engine := &RuleEngine{
		registry: registry,
	}
	engine.registerRules()
	return engine
}

// RunRules executes all rules against the given configuration
func (re *RuleEngine) RunRules(config *parser.Config, minSeverity string) []types.Issue {
	allIssues := make([]types.Issue, 0) // Initialize as empty slice, not nil

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
	// Create all built-in rules
	builtInRules := []Rule{
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

		// Azure Security Rules
		&security.AzurePublicAccessRule{},
		&security.AzureUnencryptedStorageRule{},
		&security.AzureWeakPasswordRule{},
		&security.AzureMissingTagsRule{},
		&security.AzureExposedSecretsRule{},
		&security.AzureUnrestrictedIngressRule{},
		&security.AzureDeprecatedResourcesRule{},
		&security.AzureMissingBackupRule{},
		&security.AzureWeakCryptoRule{},
		&security.AzureExcessivePermissionsRule{},
		&security.AzureOpenPortsRule{},
		&security.AzureEncryptionComplianceRule{},
		&security.AzureCostOptimizationRule{},
		&security.AzureWeakAuthenticationRule{},

		// AWS Security Rules
		&security.AWSExposedSecretsRule{},
		&security.AWSPublicS3BucketRule{},
		&security.AWSUnencryptedStorageRule{},
		&security.AWSWeakPasswordsRule{},
		&security.AWSMissingTagsRule{},
		&security.AWSUnrestrictedIngressRule{},
		&security.AWSDeprecatedResourcesRule{},
		&security.AWSMissingBackupRule{},
		&security.AWSWeakCryptoRule{},
		&security.AWSExcessivePermissionsRule{},
		&security.AWSOpenPortsRule{},
		&security.AWSEncryptionComplianceRule{},
		&security.AWSCostOptimizationRule{},

		// GCP Security Rules
		&security.GCPPublicStorageRule{},
		&security.GCPUnencryptedStorageRule{},
		&security.GCPOpenFirewallRule{},
		&security.GCPIAMOverprivilegedRule{},
		&security.GCPPublicComputeInstanceRule{},
		&security.GCPCloudSQLPublicIPRule{},
		&security.GCPKMSKeyRotationRule{},
		&security.GCPLoggingDisabledRule{},

		// Kubernetes Security Rules
		&security.KubernetesPrivilegedContainerRule{},
		&security.KubernetesRootUserRule{},
		&security.KubernetesCapabilitiesRule{},
		&security.KubernetesHostNetworkRule{},
		&security.KubernetesSecretsInEnvRule{},
		&security.KubernetesResourceLimitsRule{},
	}

	// Register all rules in both the engine and registry
	re.rules = builtInRules
	for _, rule := range builtInRules {
		re.registry.RegisterRule(rule)
	}
}

// AddCustomRule adds a custom rule to the engine
func (re *RuleEngine) AddCustomRule(rule Rule) error {
	re.rules = append(re.rules, rule)
	return re.registry.RegisterRule(rule)
}

// GetRegistry returns the rule registry
func (re *RuleEngine) GetRegistry() *DefaultRuleRegistry {
	return re.registry
}

// LoadRulesFromDirectory loads rules from a directory
func (re *RuleEngine) LoadRulesFromDirectory(path string) error {
	return re.registry.LoadRulesFromDirectory(path)
}

// LoadRuleFromFile loads a rule from a file
func (re *RuleEngine) LoadRuleFromFile(path string) error {
	return re.registry.LoadRuleFromFile(path)
}

// GetRulesByProvider returns rules for a specific provider
func (re *RuleEngine) GetRulesByProvider(provider string) []Rule {
	return re.registry.GetRulesByProvider(provider)
}

// GetRulesByCategory returns rules for a specific category
func (re *RuleEngine) GetRulesByCategory(category string) []Rule {
	return re.registry.GetRulesByCategory(category)
}

// GetRulesBySeverity returns rules for a specific severity
func (re *RuleEngine) GetRulesBySeverity(severity string) []Rule {
	return re.registry.GetRulesBySeverity(severity)
}

// EnableRule enables a rule by name
func (re *RuleEngine) EnableRule(name string) error {
	return re.registry.EnableRule(name)
}

// DisableRule disables a rule by name
func (re *RuleEngine) DisableRule(name string) error {
	return re.registry.DisableRule(name)
}

// GetRuleStats returns statistics about registered rules
func (re *RuleEngine) GetRuleStats() map[string]interface{} {
	return re.registry.GetRuleStats()
} 