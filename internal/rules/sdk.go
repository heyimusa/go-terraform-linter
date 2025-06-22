package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/go-cty/cty"
	"github.com/heyimusa/go-terraform-linter/internal/parser"
	"github.com/heyimusa/go-terraform-linter/internal/types"
)

// RuleBuilder provides a fluent interface for building rules
type RuleBuilder struct {
	definition RuleDefinition
	validators []ValidatorFunc
	processors []ProcessorFunc
}

// ValidatorFunc is a function that validates rule conditions
type ValidatorFunc func(block *types.Block, condition RuleCondition) bool

// ProcessorFunc is a function that processes matched blocks
type ProcessorFunc func(block *types.Block, condition RuleCondition) *types.Issue

// NewRuleBuilder creates a new rule builder
func NewRuleBuilder(name string) *RuleBuilder {
	return &RuleBuilder{
		definition: RuleDefinition{
			Name:       name,
			Enabled:    true,
			Version:    "1.0.0",
			Conditions: []RuleCondition{},
			Metadata:   make(map[string]string),
		},
		validators: []ValidatorFunc{},
		processors: []ProcessorFunc{},
	}
}

// WithDescription sets the rule description
func (rb *RuleBuilder) WithDescription(description string) *RuleBuilder {
	rb.definition.Description = description
	return rb
}

// WithSeverity sets the rule severity
func (rb *RuleBuilder) WithSeverity(severity string) *RuleBuilder {
	rb.definition.Severity = severity
	return rb
}

// WithCategory sets the rule category
func (rb *RuleBuilder) WithCategory(category string) *RuleBuilder {
	rb.definition.Category = category
	return rb
}

// WithProvider sets the rule provider
func (rb *RuleBuilder) WithProvider(provider string) *RuleBuilder {
	rb.definition.Provider = provider
	return rb
}

// WithTags adds tags to the rule
func (rb *RuleBuilder) WithTags(tags ...string) *RuleBuilder {
	rb.definition.Tags = append(rb.definition.Tags, tags...)
	return rb
}

// WithVersion sets the rule version
func (rb *RuleBuilder) WithVersion(version string) *RuleBuilder {
	rb.definition.Version = version
	return rb
}

// WithCompliance adds compliance standards
func (rb *RuleBuilder) WithCompliance(standards ...string) *RuleBuilder {
	rb.definition.Compliance = append(rb.definition.Compliance, standards...)
	return rb
}

// WithCWE adds CWE identifiers
func (rb *RuleBuilder) WithCWE(cweIds ...string) *RuleBuilder {
	rb.definition.CWE = append(rb.definition.CWE, cweIds...)
	return rb
}

// WithRiskScore sets the risk score (1-10)
func (rb *RuleBuilder) WithRiskScore(score int) *RuleBuilder {
	rb.definition.RiskScore = score
	return rb
}

// WithDocsURL sets the documentation URL
func (rb *RuleBuilder) WithDocsURL(url string) *RuleBuilder {
	rb.definition.DocsURL = url
	return rb
}

// WithMetadata adds metadata key-value pairs
func (rb *RuleBuilder) WithMetadata(key, value string) *RuleBuilder {
	rb.definition.Metadata[key] = value
	return rb
}

// ForResource adds a resource type condition
func (rb *RuleBuilder) ForResource(resourceType string) *RuleBuilder {
	condition := RuleCondition{
		Type:         "resource",
		ResourceType: resourceType,
		Operator:     "exists",
	}
	rb.definition.Conditions = append(rb.definition.Conditions, condition)
	return rb
}

// WithAttribute adds an attribute condition
func (rb *RuleBuilder) WithAttribute(attribute, operator string, value interface{}) *RuleBuilder {
	condition := RuleCondition{
		Type:      "attribute",
		Attribute: attribute,
		Operator:  operator,
		Value:     value,
	}
	rb.definition.Conditions = append(rb.definition.Conditions, condition)
	return rb
}

// WithAttributeEquals adds an attribute equals condition
func (rb *RuleBuilder) WithAttributeEquals(attribute string, value interface{}) *RuleBuilder {
	return rb.WithAttribute(attribute, "equals", value)
}

// WithAttributeContains adds an attribute contains condition
func (rb *RuleBuilder) WithAttributeContains(attribute, value string) *RuleBuilder {
	return rb.WithAttribute(attribute, "contains", value)
}

// WithAttributeRegex adds an attribute regex condition
func (rb *RuleBuilder) WithAttributeRegex(attribute, pattern string) *RuleBuilder {
	return rb.WithAttribute(attribute, "regex", pattern)
}

// WithAttributeExists adds an attribute exists condition
func (rb *RuleBuilder) WithAttributeExists(attribute string) *RuleBuilder {
	return rb.WithAttribute(attribute, "exists", nil)
}

// WithAttributeNotExists adds an attribute not exists condition
func (rb *RuleBuilder) WithAttributeNotExists(attribute string) *RuleBuilder {
	return rb.WithAttribute(attribute, "not_exists", nil)
}

// WithCustomMessage sets a custom message for the last condition
func (rb *RuleBuilder) WithCustomMessage(message string) *RuleBuilder {
	if len(rb.definition.Conditions) > 0 {
		rb.definition.Conditions[len(rb.definition.Conditions)-1].Message = message
	}
	return rb
}

// WithValidator adds a custom validator function
func (rb *RuleBuilder) WithValidator(validator ValidatorFunc) *RuleBuilder {
	rb.validators = append(rb.validators, validator)
	return rb
}

// WithProcessor adds a custom processor function
func (rb *RuleBuilder) WithProcessor(processor ProcessorFunc) *RuleBuilder {
	rb.processors = append(rb.processors, processor)
	return rb
}

// Build creates the final rule
func (rb *RuleBuilder) Build() (Rule, error) {
	// Validate the rule definition
	if err := rb.validateDefinition(); err != nil {
		return nil, err
	}

	// Create the rule
	rule := &SDKRule{
		ConfigurableRule: NewDynamicRule(),
		validators:       rb.validators,
		processors:       rb.processors,
	}

	// Load the rule
	if err := rule.LoadFromDefinition(rb.definition); err != nil {
		return nil, err
	}

	return rule, nil
}

func (rb *RuleBuilder) validateDefinition() error {
	if rb.definition.Name == "" {
		return fmt.Errorf("rule name is required")
	}
	if rb.definition.Description == "" {
		return fmt.Errorf("rule description is required")
	}
	if rb.definition.Severity == "" {
		return fmt.Errorf("rule severity is required")
	}
	if rb.definition.Category == "" {
		return fmt.Errorf("rule category is required")
	}
	if rb.definition.Provider == "" {
		return fmt.Errorf("rule provider is required")
	}
	if len(rb.definition.Conditions) == 0 {
		return fmt.Errorf("at least one condition is required")
	}
	return nil
}

// SDKRule represents a rule created using the SDK
type SDKRule struct {
	*ConfigurableRule
	validators []ValidatorFunc
	processors []ProcessorFunc
}

// Check implements the Rule interface with SDK enhancements
func (r *SDKRule) Check(config *parser.Config) []types.Issue {
	if !r.compiled {
		return []types.Issue{{
			Rule:        r.GetName(),
			Message:     "Rule not properly compiled",
			Description: "SDK rule was not loaded correctly",
			Severity:    "medium",
			Line:        1,
		}}
	}

	var issues []types.Issue

			for _, block := range config.Blocks {
		for i, condition := range r.definition.Conditions {
			// Use custom validators if provided
			if len(r.validators) > i && r.validators[i] != nil {
				if !r.validators[i](&block, condition) {
					continue
				}
			}

			// Use custom processors if provided
			if len(r.processors) > i && r.processors[i] != nil {
				if issue := r.processors[i](&block, condition); issue != nil {
					issues = append(issues, *issue)
				}
				continue
			}

			// Fall back to default processing
			if issue := r.checkCondition(&block, condition, i); issue != nil {
				issues = append(issues, *issue)
			}
		}
	}

	return issues
}

// Common rule patterns and helpers

// CommonPatterns provides common rule patterns
type CommonPatterns struct{}

// NewCommonPatterns creates a new common patterns helper
func NewCommonPatterns() *CommonPatterns {
	return &CommonPatterns{}
}

// PublicAccessRule creates a rule for detecting public access
func (cp *CommonPatterns) PublicAccessRule(provider, resourceType string) *RuleBuilder {
	return NewRuleBuilder(fmt.Sprintf("%s_PUBLIC_ACCESS", strings.ToUpper(provider))).
		WithDescription(fmt.Sprintf("Detects public access in %s %s", provider, resourceType)).
		WithSeverity("high").
		WithCategory("security").
		WithProvider(provider).
		WithTags("security", "public-access").
		ForResource(resourceType)
}

// UnencryptedStorageRule creates a rule for detecting unencrypted storage
func (cp *CommonPatterns) UnencryptedStorageRule(provider, resourceType string) *RuleBuilder {
	return NewRuleBuilder(fmt.Sprintf("%s_UNENCRYPTED_STORAGE", strings.ToUpper(provider))).
		WithDescription(fmt.Sprintf("Detects unencrypted storage in %s %s", provider, resourceType)).
		WithSeverity("high").
		WithCategory("encryption").
		WithProvider(provider).
		WithTags("security", "encryption", "storage").
		ForResource(resourceType)
}

// WeakPasswordRule creates a rule for detecting weak passwords
func (cp *CommonPatterns) WeakPasswordRule(provider, resourceType string) *RuleBuilder {
	return NewRuleBuilder(fmt.Sprintf("%s_WEAK_PASSWORD", strings.ToUpper(provider))).
		WithDescription(fmt.Sprintf("Detects weak passwords in %s %s", provider, resourceType)).
		WithSeverity("medium").
		WithCategory("authentication").
		WithProvider(provider).
		WithTags("security", "authentication", "password").
		ForResource(resourceType)
}

// OpenPortsRule creates a rule for detecting open ports
func (cp *CommonPatterns) OpenPortsRule(provider, resourceType string) *RuleBuilder {
	return NewRuleBuilder(fmt.Sprintf("%s_OPEN_PORTS", strings.ToUpper(provider))).
		WithDescription(fmt.Sprintf("Detects open ports in %s %s", provider, resourceType)).
		WithSeverity("high").
		WithCategory("network").
		WithProvider(provider).
		WithTags("security", "network", "ports").
		ForResource(resourceType)
}

// RuleHelpers provides helper functions for rule development
type RuleHelpers struct{}

// NewRuleHelpers creates a new rule helpers instance
func NewRuleHelpers() *RuleHelpers {
	return &RuleHelpers{}
}

// CreateIssue creates a standardized issue
func (rh *RuleHelpers) CreateIssue(ruleName, message, description, severity string, line int) types.Issue {
	return types.Issue{
		Rule:        ruleName,
		Message:     message,
		Description: description,
		Severity:    severity,
		Line:        line,
	}
}

// ExtractStringValue safely extracts string value from various types
func (rh *RuleHelpers) ExtractStringValue(value interface{}) string {
	return ctyValueToString(value)
}

// ctyValueToString converts a cty.Value to string
func ctyValueToString(value interface{}) string {
	if ctyVal, ok := value.(cty.Value); ok {
		if ctyVal.Type() == cty.String && ctyVal.IsKnown() && !ctyVal.IsNull() {
			return ctyVal.AsString()
		}
		// For non-string types, convert to string representation
		return fmt.Sprintf("%v", ctyVal)
	}
	return fmt.Sprintf("%v", value)
}

// MatchesPattern checks if a string matches a regex pattern
func (rh *RuleHelpers) MatchesPattern(text, pattern string) (bool, error) {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return false, err
	}
	return regex.MatchString(text), nil
}

// ContainsDangerousValue checks if a value contains dangerous patterns
func (rh *RuleHelpers) ContainsDangerousValue(value string, dangerousPatterns []string) bool {
	lowerValue := strings.ToLower(value)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(lowerValue, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// IsPublicCIDR checks if a CIDR represents public access
func (rh *RuleHelpers) IsPublicCIDR(cidr string) bool {
	publicCIDRs := []string{"0.0.0.0/0", "::/0", "*"}
	for _, publicCIDR := range publicCIDRs {
		if cidr == publicCIDR {
			return true
		}
	}
	return false
}

// IsDangerousPort checks if a port is considered dangerous
func (rh *RuleHelpers) IsDangerousPort(port string) bool {
	dangerousPorts := []string{"22", "23", "80", "443", "1433", "3306", "3389", "5432", "6379", "27017"}
	for _, dangerousPort := range dangerousPorts {
		if port == dangerousPort {
			return true
		}
	}
	return false
}

// HasWeakEncryption checks if encryption settings are weak
func (rh *RuleHelpers) HasWeakEncryption(encryptionValue string) bool {
	weakEncryption := []string{"none", "false", "disabled", "weak", "md5", "sha1"}
	lowerValue := strings.ToLower(encryptionValue)
	for _, weak := range weakEncryption {
		if strings.Contains(lowerValue, weak) {
			return true
		}
	}
	return false
}

// Example usage and templates

// ExampleRules provides example rule implementations
type ExampleRules struct {
	patterns *CommonPatterns
	helpers  *RuleHelpers
}

// NewExampleRules creates example rules
func NewExampleRules() *ExampleRules {
	return &ExampleRules{
		patterns: NewCommonPatterns(),
		helpers:  NewRuleHelpers(),
	}
}

// CreateAWSS3PublicReadRule creates an example AWS S3 public read rule
func (er *ExampleRules) CreateAWSS3PublicReadRule() (Rule, error) {
	return er.patterns.PublicAccessRule("aws", "aws_s3_bucket").
		WithAttributeEquals("acl", "public-read").
		WithCustomMessage("S3 bucket has public read access").
		WithCompliance("SOC2", "PCI-DSS").
		WithCWE("CWE-200").
		WithRiskScore(8).
		Build()
}

// CreateGCPFirewallOpenRule creates an example GCP firewall rule
func (er *ExampleRules) CreateGCPFirewallOpenRule() (Rule, error) {
	return er.patterns.OpenPortsRule("gcp", "google_compute_firewall").
		WithAttributeContains("source_ranges", "0.0.0.0/0").
		WithCustomMessage("Firewall rule allows access from anywhere").
		WithValidator(func(block *types.Block, condition RuleCondition) bool {
			// Custom validation: check if dangerous ports are exposed
			for _, nestedBlock := range block.Blocks {
				if nestedBlock.Type == "allow" {
					if ports, exists := nestedBlock.Attributes["ports"]; exists {
						portStr := er.helpers.ExtractStringValue(ports.Value)
						if er.helpers.IsDangerousPort(portStr) {
							return true
						}
					}
				}
			}
			return false
		}).
		WithCompliance("SOC2").
		WithCWE("CWE-284").
		WithRiskScore(7).
		Build()
}

// CreateKubernetesPrivilegedContainerRule creates an example Kubernetes rule
func (er *ExampleRules) CreateKubernetesPrivilegedContainerRule() (Rule, error) {
	return NewRuleBuilder("K8S_PRIVILEGED_CONTAINER").
		WithDescription("Detects privileged containers in Kubernetes").
		WithSeverity("critical").
		WithCategory("container-security").
		WithProvider("kubernetes").
		WithTags("security", "container", "privilege").
		ForResource("kubernetes_deployment").
		WithProcessor(func(block *types.Block, condition RuleCondition) *types.Issue {
			// Custom processor for complex Kubernetes structure
			for _, specBlock := range block.Blocks {
				if specBlock.Type == "spec" {
					for _, templateBlock := range specBlock.Blocks {
						if templateBlock.Type == "template" {
							for _, podSpecBlock := range templateBlock.Blocks {
								if podSpecBlock.Type == "spec" {
									for _, containerBlock := range podSpecBlock.Blocks {
										if containerBlock.Type == "container" {
											for _, securityContextBlock := range containerBlock.Blocks {
												if securityContextBlock.Type == "security_context" {
													if privileged, exists := securityContextBlock.Attributes["privileged"]; exists {
														if strings.Contains(er.helpers.ExtractStringValue(privileged.Value), "true") {
															return &types.Issue{
																Rule:        "K8S_PRIVILEGED_CONTAINER",
																Message:     "Container is running in privileged mode",
																Description: "Privileged containers have access to all host resources",
																Severity:    "critical",
																Line:        privileged.Range.Start.Line,
															}
														}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
			return nil
		}).
		WithCompliance("CIS", "NSA").
		WithCWE("CWE-250").
		WithRiskScore(10).
		Build()
} 