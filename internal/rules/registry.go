package rules

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// DefaultRuleRegistry implements the RuleRegistry interface
type DefaultRuleRegistry struct {
	rules    map[string]Rule
	mutex    sync.RWMutex
	enabled  map[string]bool
	metadata map[string]map[string]string
}

// NewRuleRegistry creates a new rule registry
func NewRuleRegistry() *DefaultRuleRegistry {
	return &DefaultRuleRegistry{
		rules:    make(map[string]Rule),
		enabled:  make(map[string]bool),
		metadata: make(map[string]map[string]string),
	}
}

// RegisterRule registers a rule in the registry
func (r *DefaultRuleRegistry) RegisterRule(rule Rule) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	name := rule.GetName()
	if name == "" {
		return fmt.Errorf("rule name cannot be empty")
	}

	if err := r.ValidateRule(rule); err != nil {
		return fmt.Errorf("rule validation failed: %w", err)
	}

	r.rules[name] = rule
	r.enabled[name] = true

	// Store metadata for advanced rules
	if advRule, ok := rule.(AdvancedRule); ok {
		r.metadata[name] = map[string]string{
			"category":    advRule.GetCategory(),
			"provider":    advRule.GetProvider(),
			"version":     advRule.GetVersion(),
			"docs_url":    advRule.GetDocumentationURL(),
			"risk_score":  fmt.Sprintf("%d", advRule.GetRiskScore()),
			"compliance":  strings.Join(advRule.GetCompliance(), ","),
			"cwe":         strings.Join(advRule.GetCWE(), ","),
		}
	}

	return nil
}

// GetRule retrieves a rule by name
func (r *DefaultRuleRegistry) GetRule(name string) (Rule, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	rule, exists := r.rules[name]
	if !exists {
		return nil, fmt.Errorf("rule '%s' not found", name)
	}

	return rule, nil
}

// GetRulesByProvider returns all rules for a specific provider
func (r *DefaultRuleRegistry) GetRulesByProvider(provider string) []Rule {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	var result []Rule
	for _, rule := range r.rules {
		if rule.GetProvider() == provider {
			result = append(result, rule)
		}
	}
	return result
}

// GetRulesByCategory returns all rules for a specific category
func (r *DefaultRuleRegistry) GetRulesByCategory(category string) []Rule {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	var result []Rule
	for _, rule := range r.rules {
		if rule.GetCategory() == category {
			result = append(result, rule)
		}
	}
	return result
}

// GetRulesBySeverity returns all rules for a specific severity
func (r *DefaultRuleRegistry) GetRulesBySeverity(severity string) []Rule {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	var result []Rule
	for _, rule := range r.rules {
		if strings.EqualFold(rule.GetSeverity(), severity) {
			result = append(result, rule)
		}
	}
	return result
}

// GetAllRules returns all registered rules
func (r *DefaultRuleRegistry) GetAllRules() []Rule {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	var result []Rule
	for _, rule := range r.rules {
		result = append(result, rule)
	}
	return result
}

// LoadRulesFromDirectory loads all rule files from a directory
func (r *DefaultRuleRegistry) LoadRulesFromDirectory(path string) error {
	return filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(filePath))
		if ext == ".json" || ext == ".yaml" || ext == ".yml" {
			return r.LoadRuleFromFile(filePath)
		}

		return nil
	})
}

// LoadRuleFromFile loads a rule from a file
func (r *DefaultRuleRegistry) LoadRuleFromFile(path string) error {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read rule file '%s': %w", path, err)
	}

	var definition RuleDefinition
	ext := strings.ToLower(filepath.Ext(path))

	switch ext {
	case ".json":
		if err := json.Unmarshal(data, &definition); err != nil {
			return fmt.Errorf("failed to parse JSON rule file '%s': %w", path, err)
		}
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &definition); err != nil {
			return fmt.Errorf("failed to parse YAML rule file '%s': %w", path, err)
		}
	default:
		return fmt.Errorf("unsupported rule file format: %s", ext)
	}

	// Create dynamic rule from definition
	dynamicRule := NewDynamicRule()
	if err := dynamicRule.LoadFromDefinition(definition); err != nil {
		return fmt.Errorf("failed to load rule from definition in '%s': %w", path, err)
	}

	return r.RegisterRule(dynamicRule)
}

// ValidateRule validates a rule
func (r *DefaultRuleRegistry) ValidateRule(rule Rule) error {
	if rule.GetName() == "" {
		return fmt.Errorf("rule name is required")
	}

	if rule.GetDescription() == "" {
		return fmt.Errorf("rule description is required")
	}

	validSeverities := []string{"low", "medium", "high", "critical"}
	severity := strings.ToLower(rule.GetSeverity())
	isValidSeverity := false
	for _, valid := range validSeverities {
		if severity == valid {
			isValidSeverity = true
			break
		}
	}
	if !isValidSeverity {
		return fmt.Errorf("invalid severity '%s', must be one of: %s", 
			rule.GetSeverity(), strings.Join(validSeverities, ", "))
	}

	if rule.GetCategory() == "" {
		return fmt.Errorf("rule category is required")
	}

	if rule.GetProvider() == "" {
		return fmt.Errorf("rule provider is required")
	}

	// Additional validation for dynamic rules
	if dynRule, ok := rule.(DynamicRule); ok {
		if err := dynRule.Validate(); err != nil {
			return fmt.Errorf("dynamic rule validation failed: %w", err)
		}
	}

	return nil
}

// EnableRule enables a rule
func (r *DefaultRuleRegistry) EnableRule(name string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, exists := r.rules[name]; !exists {
		return fmt.Errorf("rule '%s' not found", name)
	}

	r.enabled[name] = true
	return nil
}

// DisableRule disables a rule
func (r *DefaultRuleRegistry) DisableRule(name string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, exists := r.rules[name]; !exists {
		return fmt.Errorf("rule '%s' not found", name)
	}

	r.enabled[name] = false
	return nil
}

// IsRuleEnabled checks if a rule is enabled
func (r *DefaultRuleRegistry) IsRuleEnabled(name string) bool {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	enabled, exists := r.enabled[name]
	return exists && enabled
}

// GetRuleMetadata returns metadata for a rule
func (r *DefaultRuleRegistry) GetRuleMetadata(name string) map[string]string {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	if metadata, exists := r.metadata[name]; exists {
		// Return a copy to prevent external modification
		result := make(map[string]string)
		for k, v := range metadata {
			result[k] = v
		}
		return result
	}

	return make(map[string]string)
}

// GetEnabledRules returns only enabled rules
func (r *DefaultRuleRegistry) GetEnabledRules() []Rule {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	var result []Rule
	for name, rule := range r.rules {
		if r.enabled[name] {
			result = append(result, rule)
		}
	}
	return result
}

// GetRuleStats returns statistics about registered rules
func (r *DefaultRuleRegistry) GetRuleStats() map[string]interface{} {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	stats := make(map[string]interface{})
	stats["total_rules"] = len(r.rules)

	// Count by provider
	providerCounts := make(map[string]int)
	categoryCounts := make(map[string]int)
	severityCounts := make(map[string]int)
	enabledCount := 0

	for name, rule := range r.rules {
		providerCounts[rule.GetProvider()]++
		categoryCounts[rule.GetCategory()]++
		severityCounts[strings.ToLower(rule.GetSeverity())]++
		
		if r.enabled[name] {
			enabledCount++
		}
	}

	stats["enabled_rules"] = enabledCount
	stats["disabled_rules"] = len(r.rules) - enabledCount
	stats["by_provider"] = providerCounts
	stats["by_category"] = categoryCounts
	stats["by_severity"] = severityCounts

	return stats
} 