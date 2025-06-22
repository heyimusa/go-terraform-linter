package rules

import (
	"github.com/heyimusa/go-terraform-linter/internal/parser"
	"github.com/heyimusa/go-terraform-linter/internal/types"
)

// Rule interface that all security rules must implement
type Rule interface {
	Check(config *parser.Config) []types.Issue
	GetName() string
	GetDescription() string
	GetSeverity() string
	GetCategory() string
	GetProvider() string
	GetTags() []string
	GetVersion() string
}

// AdvancedRule interface for rules with additional capabilities
type AdvancedRule interface {
	Rule
	GetDocumentationURL() string
	GetFixSuggestion(issue types.Issue) string
	GetCompliance() []string // e.g., ["SOC2", "PCI-DSS", "HIPAA"]
	GetCWE() []string        // Common Weakness Enumeration IDs
	IsEnabled() bool
	GetRiskScore() int       // 1-10 risk score
}

// DynamicRule interface for rules loaded at runtime
type DynamicRule interface {
	AdvancedRule
	GetRuleDefinition() RuleDefinition
	LoadFromDefinition(def RuleDefinition) error
	Validate() error
}

// RuleDefinition represents a rule configuration
type RuleDefinition struct {
	ID           string            `json:"id" yaml:"id"`
	Name         string            `json:"name" yaml:"name"`
	Description  string            `json:"description" yaml:"description"`
	Severity     string            `json:"severity" yaml:"severity"`
	Category     string            `json:"category" yaml:"category"`
	Provider     string            `json:"provider" yaml:"provider"`
	Tags         []string          `json:"tags" yaml:"tags"`
	Version      string            `json:"version" yaml:"version"`
	Enabled      bool              `json:"enabled" yaml:"enabled"`
	RiskScore    int               `json:"risk_score" yaml:"risk_score"`
	Compliance   []string          `json:"compliance" yaml:"compliance"`
	CWE          []string          `json:"cwe" yaml:"cwe"`
	DocsURL      string            `json:"docs_url" yaml:"docs_url"`
	Conditions   []RuleCondition   `json:"conditions" yaml:"conditions"`
	Metadata     map[string]string `json:"metadata" yaml:"metadata"`
}

// RuleCondition represents a condition for rule matching
type RuleCondition struct {
	Type         string      `json:"type" yaml:"type"`                   // "resource", "attribute", "block"
	ResourceType string      `json:"resource_type" yaml:"resource_type"` // e.g., "aws_s3_bucket"
	Attribute    string      `json:"attribute" yaml:"attribute"`         // e.g., "acl"
	Operator     string      `json:"operator" yaml:"operator"`           // "equals", "contains", "regex", "exists", "not_exists"
	Value        interface{} `json:"value" yaml:"value"`                 // Expected value
	Message      string      `json:"message" yaml:"message"`             // Custom message for this condition
}

// RuleRegistry manages rule registration and discovery
type RuleRegistry interface {
	RegisterRule(rule Rule) error
	GetRule(name string) (Rule, error)
	GetRulesByProvider(provider string) []Rule
	GetRulesByCategory(category string) []Rule
	GetRulesBySeverity(severity string) []Rule
	GetAllRules() []Rule
	LoadRulesFromDirectory(path string) error
	LoadRuleFromFile(path string) error
	ValidateRule(rule Rule) error
} 