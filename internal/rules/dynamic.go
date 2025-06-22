package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/go-cty/cty"
	"github.com/heyimusa/go-terraform-linter/internal/parser"
	"github.com/heyimusa/go-terraform-linter/internal/types"
)

// ConfigurableRule represents a rule that can be configured dynamically
type ConfigurableRule struct {
	definition RuleDefinition
	compiled   bool
	regexes    map[string]*regexp.Regexp
}

// NewDynamicRule creates a new dynamic rule
func NewDynamicRule() *ConfigurableRule {
	return &ConfigurableRule{
		regexes: make(map[string]*regexp.Regexp),
	}
}

// LoadFromDefinition loads rule configuration from a definition
func (r *ConfigurableRule) LoadFromDefinition(def RuleDefinition) error {
	r.definition = def
	
	// Compile regex patterns
	for i, condition := range def.Conditions {
		if condition.Operator == "regex" {
			if valueStr, ok := condition.Value.(string); ok {
				regex, err := regexp.Compile(valueStr)
				if err != nil {
					return fmt.Errorf("invalid regex pattern in condition %d: %w", i, err)
				}
				r.regexes[fmt.Sprintf("condition_%d", i)] = regex
			}
		}
	}
	
	r.compiled = true
	return nil
}

// GetRuleDefinition returns the rule definition
func (r *ConfigurableRule) GetRuleDefinition() RuleDefinition {
	return r.definition
}

// Validate validates the rule configuration
func (r *ConfigurableRule) Validate() error {
	if r.definition.ID == "" {
		return fmt.Errorf("rule ID is required")
	}
	
	if r.definition.Name == "" {
		return fmt.Errorf("rule name is required")
	}
	
	if len(r.definition.Conditions) == 0 {
		return fmt.Errorf("at least one condition is required")
	}
	
	// Validate conditions
	for i, condition := range r.definition.Conditions {
		if err := r.validateCondition(condition, i); err != nil {
			return err
		}
	}
	
	return nil
}

func (r *ConfigurableRule) validateCondition(condition RuleCondition, index int) error {
	validTypes := []string{"resource", "attribute", "block"}
	if !contains(validTypes, condition.Type) {
		return fmt.Errorf("condition %d: invalid type '%s', must be one of: %s", 
			index, condition.Type, strings.Join(validTypes, ", "))
	}
	
	validOperators := []string{"equals", "contains", "regex", "exists", "not_exists", "greater_than", "less_than"}
	if !contains(validOperators, condition.Operator) {
		return fmt.Errorf("condition %d: invalid operator '%s', must be one of: %s", 
			index, condition.Operator, strings.Join(validOperators, ", "))
	}
	
	if condition.Type == "resource" && condition.ResourceType == "" {
		return fmt.Errorf("condition %d: resource_type is required for resource conditions", index)
	}
	
	if condition.Type == "attribute" && condition.Attribute == "" {
		return fmt.Errorf("condition %d: attribute is required for attribute conditions", index)
	}
	
	return nil
}

// Rule interface implementation
func (r *ConfigurableRule) GetName() string {
	return r.definition.Name
}

func (r *ConfigurableRule) GetDescription() string {
	return r.definition.Description
}

func (r *ConfigurableRule) GetSeverity() string {
	return r.definition.Severity
}

func (r *ConfigurableRule) GetCategory() string {
	return r.definition.Category
}

func (r *ConfigurableRule) GetProvider() string {
	return r.definition.Provider
}

func (r *ConfigurableRule) GetTags() []string {
	return r.definition.Tags
}

func (r *ConfigurableRule) GetVersion() string {
	return r.definition.Version
}

// AdvancedRule interface implementation
func (r *ConfigurableRule) GetDocumentationURL() string {
	return r.definition.DocsURL
}

func (r *ConfigurableRule) GetFixSuggestion(issue types.Issue) string {
	// Generate fix suggestion based on rule type and conditions
	for _, condition := range r.definition.Conditions {
		if condition.Message != "" {
			return fmt.Sprintf("Fix suggestion: %s", condition.Message)
		}
	}
	return "Please review the configuration and apply security best practices"
}

func (r *ConfigurableRule) GetCompliance() []string {
	return r.definition.Compliance
}

func (r *ConfigurableRule) GetCWE() []string {
	return r.definition.CWE
}

func (r *ConfigurableRule) IsEnabled() bool {
	return r.definition.Enabled
}

func (r *ConfigurableRule) GetRiskScore() int {
	return r.definition.RiskScore
}

// Check implements the main rule logic
func (r *ConfigurableRule) Check(config *parser.Config) []types.Issue {
	if !r.compiled {
		return []types.Issue{{
			Rule:        r.GetName(),
			Message:     "Rule not properly compiled",
			Description: "Dynamic rule was not loaded correctly",
			Severity:    "medium",
			Line:        1,
		}}
	}
	
	var issues []types.Issue
	
	for _, block := range config.Blocks {
		for i, condition := range r.definition.Conditions {
			if issue := r.checkCondition(&block, condition, i); issue != nil {
				issues = append(issues, *issue)
			}
		}
	}
	
	return issues
}

func (r *ConfigurableRule) checkCondition(block *types.Block, condition RuleCondition, conditionIndex int) *types.Issue {
	switch condition.Type {
	case "resource":
		return r.checkResourceCondition(block, condition, conditionIndex)
	case "attribute":
		return r.checkAttributeCondition(block, condition, conditionIndex)
	case "block":
		return r.checkBlockCondition(block, condition, conditionIndex)
	}
	return nil
}

func (r *ConfigurableRule) checkResourceCondition(block *types.Block, condition RuleCondition, conditionIndex int) *types.Issue {
	if block.Type != "resource" || len(block.Labels) == 0 {
		return nil
	}
	
	resourceType := block.Labels[0]
	if condition.ResourceType != "" && resourceType != condition.ResourceType {
		return nil
	}
	
	return r.evaluateCondition(block, condition, conditionIndex, resourceType)
}

func (r *ConfigurableRule) checkAttributeCondition(block *types.Block, condition RuleCondition, conditionIndex int) *types.Issue {
	if condition.ResourceType != "" {
		if block.Type != "resource" || len(block.Labels) == 0 || block.Labels[0] != condition.ResourceType {
			return nil
		}
	}
	
	attr, exists := block.Attributes[condition.Attribute]
	if !exists && condition.Operator == "not_exists" {
		return &types.Issue{
			Rule:        r.GetName(),
			Message:     r.getConditionMessage(condition),
			Description: r.GetDescription(),
			Severity:    r.GetSeverity(),
			Line:        block.Range.Start.Line,
		}
	}
	
	if !exists {
		return nil
	}
	
	return r.evaluateAttributeCondition(&attr, condition, conditionIndex)
}

func (r *ConfigurableRule) checkBlockCondition(block *types.Block, condition RuleCondition, conditionIndex int) *types.Issue {
	// Check nested blocks
	for _, nestedBlock := range block.Blocks {
		if condition.ResourceType != "" && nestedBlock.Type != condition.ResourceType {
			continue
		}
		
		if issue := r.evaluateCondition(&nestedBlock, condition, conditionIndex, nestedBlock.Type); issue != nil {
			return issue
		}
	}
	return nil
}

func (r *ConfigurableRule) evaluateCondition(block *types.Block, condition RuleCondition, conditionIndex int, target string) *types.Issue {
	switch condition.Operator {
	case "exists":
		return &types.Issue{
			Rule:        r.GetName(),
			Message:     r.getConditionMessage(condition),
			Description: r.GetDescription(),
			Severity:    r.GetSeverity(),
			Line:        block.Range.Start.Line,
		}
	case "equals":
		if target == fmt.Sprintf("%v", condition.Value) {
			return &types.Issue{
				Rule:        r.GetName(),
				Message:     r.getConditionMessage(condition),
				Description: r.GetDescription(),
				Severity:    r.GetSeverity(),
				Line:        block.Range.Start.Line,
			}
		}
	case "contains":
		if strings.Contains(target, fmt.Sprintf("%v", condition.Value)) {
			return &types.Issue{
				Rule:        r.GetName(),
				Message:     r.getConditionMessage(condition),
				Description: r.GetDescription(),
				Severity:    r.GetSeverity(),
				Line:        block.Range.Start.Line,
			}
		}
	case "regex":
		if regex, exists := r.regexes[fmt.Sprintf("condition_%d", conditionIndex)]; exists {
			if regex.MatchString(target) {
				return &types.Issue{
					Rule:        r.GetName(),
					Message:     r.getConditionMessage(condition),
					Description: r.GetDescription(),
					Severity:    r.GetSeverity(),
					Line:        block.Range.Start.Line,
				}
			}
		}
	}
	return nil
}

func (r *ConfigurableRule) evaluateAttributeCondition(attr *types.Attribute, condition RuleCondition, conditionIndex int) *types.Issue {
	value := r.extractAttributeValue(attr.Value)
	
	switch condition.Operator {
	case "exists":
		return &types.Issue{
			Rule:        r.GetName(),
			Message:     r.getConditionMessage(condition),
			Description: r.GetDescription(),
			Severity:    r.GetSeverity(),
			Line:        attr.Range.Start.Line,
		}
	case "equals":
		if value == fmt.Sprintf("%v", condition.Value) {
			return &types.Issue{
				Rule:        r.GetName(),
				Message:     r.getConditionMessage(condition),
				Description: r.GetDescription(),
				Severity:    r.GetSeverity(),
				Line:        attr.Range.Start.Line,
			}
		}
	case "contains":
		if strings.Contains(value, fmt.Sprintf("%v", condition.Value)) {
			return &types.Issue{
				Rule:        r.GetName(),
				Message:     r.getConditionMessage(condition),
				Description: r.GetDescription(),
				Severity:    r.GetSeverity(),
				Line:        attr.Range.Start.Line,
			}
		}
	case "regex":
		if regex, exists := r.regexes[fmt.Sprintf("condition_%d", conditionIndex)]; exists {
			if regex.MatchString(value) {
				return &types.Issue{
					Rule:        r.GetName(),
					Message:     r.getConditionMessage(condition),
					Description: r.GetDescription(),
					Severity:    r.GetSeverity(),
					Line:        attr.Range.Start.Line,
				}
			}
		}
	}
	return nil
}

func (r *ConfigurableRule) extractAttributeValue(value interface{}) string {
	if ctyVal, ok := value.(cty.Value); ok {
		if ctyVal.Type() == cty.String && ctyVal.IsKnown() && !ctyVal.IsNull() {
			return ctyVal.AsString()
		}
		// For non-string types, convert to string representation
		return fmt.Sprintf("%v", ctyVal)
	}
	return fmt.Sprintf("%v", value)
}

func (r *ConfigurableRule) getConditionMessage(condition RuleCondition) string {
	if condition.Message != "" {
		return condition.Message
	}
	return fmt.Sprintf("Condition matched: %s %s %v", condition.Attribute, condition.Operator, condition.Value)
}

// Helper function
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
} 