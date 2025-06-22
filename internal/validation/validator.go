package validation

import (
	"fmt"
	"regexp"

	"github.com/heyimusa/go-terraform-linter/internal/parser"
	"github.com/heyimusa/go-terraform-linter/internal/types"
)

// RuleValidator provides validation and confidence scoring for security rules
type RuleValidator struct {
	contextRules map[string][]ContextRule
	whitelist    map[string][]string
	blacklist    map[string][]string
}

// ContextRule defines validation rules based on context
type ContextRule struct {
	RuleName    string
	Conditions  []Condition
	Confidence  float64
	Description string
}

// Condition defines a validation condition
type Condition struct {
	Type      string // "attribute_exists", "attribute_value", "resource_type", "context"
	Field     string
	Value     interface{}
	Operator  string // "equals", "contains", "regex", "exists", "not_exists"
}

// ValidationResult represents the result of rule validation
type ValidationResult struct {
	IsValid    bool
	Confidence float64
	Reason     string
	Suggestions []string
}

// NewRuleValidator creates a new rule validator
func NewRuleValidator() *RuleValidator {
	validator := &RuleValidator{
		contextRules: make(map[string][]ContextRule),
		whitelist:    make(map[string][]string),
		blacklist:    make(map[string][]string),
	}
	
	// Initialize default validation rules
	validator.initializeDefaultRules()
	
	return validator
}

// ValidateIssue validates a security issue and returns confidence score
func (v *RuleValidator) ValidateIssue(issue types.Issue, config *parser.Config) ValidationResult {
	result := ValidationResult{
		IsValid:    true,
		Confidence: 1.0,
		Reason:     "Issue validated successfully",
	}
	
	// Check whitelist
	if v.isWhitelisted(issue.Rule) {
		result.IsValid = false
		result.Confidence = 0.0
		result.Reason = "Issue is whitelisted for this rule"
		return result
	}
	
	// Check blacklist
	if v.isBlacklisted(issue.Rule) {
		result.IsValid = false
		result.Confidence = 0.0
		result.Reason = "Issue is blacklisted for this rule"
		return result
	}
	
	// Apply context rules
	contextRules := v.contextRules[issue.Rule]
	for _, rule := range contextRules {
		if v.matchesContext(rule, issue, config) {
			result.Confidence *= rule.Confidence
			if result.Confidence < 0.5 {
				result.IsValid = false
				result.Reason = fmt.Sprintf("Low confidence due to context: %s", rule.Description)
			}
		}
	}
	
	// Apply rule-specific validations
	switch issue.Rule {
	case "AZURE_EXPOSED_SECRETS", "AWS_EXPOSED_SECRETS":
		result = v.validateSecretDetection(issue, config)
	case "AZURE_PUBLIC_ACCESS", "AWS_PUBLIC_S3_BUCKET":
		result = v.validatePublicAccess(issue, config)
	case "AZURE_UNENCRYPTED_STORAGE", "AWS_UNENCRYPTED_STORAGE":
		result = v.validateEncryption(issue, config)
	case "AZURE_UNRESTRICTED_INGRESS", "AWS_UNRESTRICTED_INGRESS":
		result = v.validateNetworkAccess(issue, config)
	}
	
	return result
}

// validateSecretDetection validates secret detection rules
func (v *RuleValidator) validateSecretDetection(issue types.Issue, config *parser.Config) ValidationResult {
	result := ValidationResult{
		IsValid:    true,
		Confidence: 1.0,
		Reason:     "Secret detection validated",
	}
	
	// Check if the detected value is actually a secret
	secretPatterns := []string{
		`^[A-Za-z0-9+/]{20,}={0,2}$`, // Base64 encoded secrets
		`^[A-Za-z0-9]{20,}$`,         // Long alphanumeric strings
		`^[a-f0-9]{32,}$`,           // MD5/SHA hashes
		`^[a-f0-9]{64}$`,            // SHA256 hashes
		`^sk-[A-Za-z0-9]{20,}$`,     // Stripe secret keys
		`^AKIA[A-Z0-9]{16}$`,        // AWS access keys
		`^[A-Za-z0-9]{40}$`,         // GitHub tokens
	}
	
	// Extract the actual value from the issue
	detectedValue := v.extractValueFromIssue(issue, config)
	
	// Check if it matches any secret pattern
	matchesPattern := false
	for _, pattern := range secretPatterns {
		if matched, _ := regexp.MatchString(pattern, detectedValue); matched {
			matchesPattern = true
			break
		}
	}
	
	// Check for common false positives
	falsePositivePatterns := []string{
		`^var\.`,                    // Variable references
		`^data\.`,                   // Data source references
		`^local\.`,                  // Local value references
		`^[a-z0-9-]+$`,             // Simple resource names
		`^ami-[a-f0-9]{8}$`,        // AMI IDs
		`^sg-[a-f0-9]{8}$`,         // Security group IDs
	}
	
	for _, pattern := range falsePositivePatterns {
		if matched, _ := regexp.MatchString(pattern, detectedValue); matched {
			result.IsValid = false
			result.Confidence = 0.1
			result.Reason = "Likely false positive - matches common resource pattern"
			return result
		}
	}
	
	if !matchesPattern {
		result.Confidence = 0.3
		result.Reason = "Detected value doesn't match common secret patterns"
	}
	
	return result
}

// validatePublicAccess validates public access rules
func (v *RuleValidator) validatePublicAccess(issue types.Issue, config *parser.Config) ValidationResult {
	result := ValidationResult{
		IsValid:    true,
		Confidence: 1.0,
		Reason:     "Public access validation passed",
	}
	
	// Check if this is a development environment
	if v.isDevelopmentEnvironment(config) {
		result.Confidence = 0.7
		result.Reason = "Public access in development environment - lower risk"
		result.Suggestions = []string{
			"Consider restricting access in production",
			"Use environment-specific configurations",
		}
	}
	
	// Check if there are compensating controls
	if v.hasCompensatingControls(issue, config) {
		result.Confidence = 0.8
		result.Reason = "Public access detected but compensating controls exist"
	}
	
	return result
}

// validateEncryption validates encryption rules
func (v *RuleValidator) validateEncryption(issue types.Issue, config *parser.Config) ValidationResult {
	result := ValidationResult{
		IsValid:    true,
		Confidence: 1.0,
		Reason:     "Encryption validation passed",
	}
	
	// Check if encryption is enabled by default for this resource type
	if v.isEncryptionEnabledByDefault(issue, config) {
		result.Confidence = 0.6
		result.Reason = "Encryption may be enabled by default for this resource type"
		result.Suggestions = []string{
			"Verify encryption status in cloud console",
			"Explicitly enable encryption for compliance",
		}
	}
	
	return result
}

// validateNetworkAccess validates network access rules
func (v *RuleValidator) validateNetworkAccess(issue types.Issue, config *parser.Config) ValidationResult {
	result := ValidationResult{
		IsValid:    true,
		Confidence: 1.0,
		Reason:     "Network access validation passed",
	}
	
	// Check if this is a load balancer or bastion host
	if v.isLoadBalancerOrBastion(issue, config) {
		result.Confidence = 0.8
		result.Reason = "Unrestricted access may be intentional for load balancer/bastion"
		result.Suggestions = []string{
			"Verify this is intentional",
			"Consider restricting access to specific IP ranges",
		}
	}
	
	return result
}

// isWhitelisted checks if an issue is whitelisted for a rule
func (v *RuleValidator) isWhitelisted(ruleName string) bool {
	whitelist := v.whitelist[ruleName]
	return len(whitelist) > 0 // Simplified: if any whitelist exists for the rule, skip
}

// isBlacklisted checks if an issue is blacklisted for a rule
func (v *RuleValidator) isBlacklisted(ruleName string) bool {
	blacklist := v.blacklist[ruleName]
	return len(blacklist) > 0 // Simplified: if any blacklist exists for the rule, skip
}

// matchesContext checks if an issue matches context rules
func (v *RuleValidator) matchesContext(rule ContextRule, issue types.Issue, config *parser.Config) bool {
	for _, condition := range rule.Conditions {
		if !v.evaluateCondition(condition, issue, config) {
			return false
		}
	}
	return true
}

// evaluateCondition evaluates a single condition
func (v *RuleValidator) evaluateCondition(condition Condition, issue types.Issue, config *parser.Config) bool {
	switch condition.Type {
	case "attribute_exists":
		return v.attributeExists(condition.Field, issue, config)
	case "attribute_value":
		return v.attributeValueMatches(condition.Field, condition.Value, condition.Operator, issue, config)
	case "resource_type":
		return v.resourceTypeMatches(condition.Value.(string), issue, config)
	case "context":
		return v.contextMatches(condition.Field, condition.Value, issue, config)
	}
	return false
}

// Helper methods for condition evaluation
func (v *RuleValidator) attributeExists(field string, issue types.Issue, config *parser.Config) bool {
	// Implementation would check if the specified attribute exists
	return true
}

func (v *RuleValidator) attributeValueMatches(field string, expectedValue interface{}, operator string, issue types.Issue, config *parser.Config) bool {
	// Implementation would check if attribute value matches expected value
	return true
}

func (v *RuleValidator) resourceTypeMatches(expectedType string, issue types.Issue, config *parser.Config) bool {
	// Implementation would check if resource type matches
	return true
}

func (v *RuleValidator) contextMatches(context string, expectedValue interface{}, issue types.Issue, config *parser.Config) bool {
	// Implementation would check context-specific conditions
	return true
}

// extractValueFromIssue extracts the actual value from an issue
func (v *RuleValidator) extractValueFromIssue(issue types.Issue, config *parser.Config) string {
	// Implementation would extract the actual value that triggered the issue
	return ""
}

// isDevelopmentEnvironment checks if this is a development environment
func (v *RuleValidator) isDevelopmentEnvironment(config *parser.Config) bool {
	// Implementation would check for development environment indicators
	return false
}

// hasCompensatingControls checks if compensating controls exist
func (v *RuleValidator) hasCompensatingControls(issue types.Issue, config *parser.Config) bool {
	// Implementation would check for compensating security controls
	return false
}

// isEncryptionEnabledByDefault checks if encryption is enabled by default
func (v *RuleValidator) isEncryptionEnabledByDefault(issue types.Issue, config *parser.Config) bool {
	// Implementation would check if encryption is enabled by default for the resource type
	return false
}

// isLoadBalancerOrBastion checks if this is a load balancer or bastion host
func (v *RuleValidator) isLoadBalancerOrBastion(issue types.Issue, config *parser.Config) bool {
	// Implementation would check if the resource is a load balancer or bastion host
	return false
}

// initializeDefaultRules initializes default validation rules
func (v *RuleValidator) initializeDefaultRules() {
	// Add default context rules for common scenarios
	v.contextRules["AZURE_EXPOSED_SECRETS"] = []ContextRule{
		{
			RuleName: "development_environment",
			Conditions: []Condition{
				{Type: "context", Field: "environment", Value: "dev", Operator: "equals"},
			},
			Confidence:  0.8,
			Description: "Lower confidence in development environments",
		},
	}
	
	// Add whitelist patterns
	v.whitelist["AZURE_EXPOSED_SECRETS"] = []string{
		"examples/",
		"test/",
		"*.example.tf",
	}
	
	// Add blacklist patterns
	v.blacklist["MISSING_TAGS"] = []string{
		"data/",
		"modules/",
	}
} 