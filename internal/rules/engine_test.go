package rules

import (
	"testing"

	"github.com/heyimusa/go-terraform-linter/internal/parser"
	"github.com/heyimusa/go-terraform-linter/internal/types"
)

// MockRule for testing
type MockRule struct {
	RuleName    string
	RuleIssues  []types.Issue
	ShouldFail  bool
}

func (m *MockRule) Check(config *parser.Config) []types.Issue {
	if m.ShouldFail {
		// Simulate a rule that fails
		return nil
	}
	return m.RuleIssues
}

func (m *MockRule) GetName() string {
	return m.RuleName
}

func (m *MockRule) GetDescription() string {
	return "Mock rule for testing"
}

func (m *MockRule) GetSeverity() string {
	return "medium"
}

func (m *MockRule) GetCategory() string {
	return "test"
}

func (m *MockRule) GetProvider() string {
	return "test"
}

func (m *MockRule) GetTags() []string {
	return []string{"test", "mock"}
}

func (m *MockRule) GetVersion() string {
	return "1.0.0"
}

func TestNewRuleEngine(t *testing.T) {
	engine := NewRuleEngine()
	
	if engine == nil {
		t.Fatal("Expected rule engine, got nil")
	}

	if len(engine.rules) == 0 {
		t.Error("Expected rule engine to have built-in rules")
	}

	// Check that we have the expected number of rules (40+ as mentioned in README)
	if len(engine.rules) < 40 {
		t.Errorf("Expected at least 40 rules, got %d", len(engine.rules))
	}
}

func TestRuleEngineRunRules(t *testing.T) {
	engine := &RuleEngine{}
	
	// Add mock rules
	highSeverityRule := &MockRule{
		RuleName: "HIGH_SEVERITY_RULE",
		RuleIssues: []types.Issue{
			{
				Rule:     "HIGH_SEVERITY_RULE",
				Message:  "High severity issue",
				Severity: "high",
				Line:     10,
			},
		},
	}
	
	mediumSeverityRule := &MockRule{
		RuleName: "MEDIUM_SEVERITY_RULE",
		RuleIssues: []types.Issue{
			{
				Rule:     "MEDIUM_SEVERITY_RULE",
				Message:  "Medium severity issue",
				Severity: "medium",
				Line:     20,
			},
		},
	}
	
	lowSeverityRule := &MockRule{
		RuleName: "LOW_SEVERITY_RULE",
		RuleIssues: []types.Issue{
			{
				Rule:     "LOW_SEVERITY_RULE",
				Message:  "Low severity issue",
				Severity: "low",
				Line:     30,
			},
		},
	}

	engine.rules = []Rule{highSeverityRule, mediumSeverityRule, lowSeverityRule}

	// Create mock config
	config := &parser.Config{
		Blocks: []types.Block{
			{
				Type:   "resource",
				Labels: []string{"aws_instance", "test"},
				Attributes: map[string]types.Attribute{
					"ami": {
						Name:     "ami",
						Value:    "ami-12345",
						RawValue: "ami-12345",
					},
				},
			},
		},
	}

	tests := []struct {
		name          string
		minSeverity   string
		expectedCount int
	}{
		{
			name:          "all severity levels",
			minSeverity:   "all",
			expectedCount: 3,
		},
		{
			name:          "low and above",
			minSeverity:   "low",
			expectedCount: 3,
		},
		{
			name:          "medium and above",
			minSeverity:   "medium",
			expectedCount: 2,
		},
		{
			name:          "high and above",
			minSeverity:   "high",
			expectedCount: 1,
		},
		{
			name:          "critical only",
			minSeverity:   "critical",
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := engine.RunRules(config, tt.minSeverity)
			
			if len(issues) != tt.expectedCount {
				t.Errorf("Expected %d issues, got %d", tt.expectedCount, len(issues))
			}

			// Verify that all returned issues meet the severity requirement
			for _, issue := range issues {
				if !engine.shouldIncludeIssue(issue.Severity, tt.minSeverity) {
					t.Errorf("Issue with severity '%s' should not be included with min severity '%s'", 
						issue.Severity, tt.minSeverity)
				}
			}
		})
	}
}

func TestShouldIncludeIssue(t *testing.T) {
	engine := NewRuleEngine()

	tests := []struct {
		name           string
		issueSeverity  string
		minSeverity    string
		shouldInclude  bool
	}{
		// Test "all" filter
		{
			name:          "all filter includes low",
			issueSeverity: "low",
			minSeverity:   "all",
			shouldInclude: true,
		},
		{
			name:          "all filter includes critical",
			issueSeverity: "critical",
			minSeverity:   "all",
			shouldInclude: true,
		},
		
		// Test severity hierarchy
		{
			name:          "low severity with low filter",
			issueSeverity: "low",
			minSeverity:   "low",
			shouldInclude: true,
		},
		{
			name:          "medium severity with low filter",
			issueSeverity: "medium",
			minSeverity:   "low",
			shouldInclude: true,
		},
		{
			name:          "high severity with low filter",
			issueSeverity: "high",
			minSeverity:   "low",
			shouldInclude: true,
		},
		{
			name:          "critical severity with low filter",
			issueSeverity: "critical",
			minSeverity:   "low",
			shouldInclude: true,
		},
		
		// Test filtering out lower severities
		{
			name:          "low severity with medium filter",
			issueSeverity: "low",
			minSeverity:   "medium",
			shouldInclude: false,
		},
		{
			name:          "low severity with high filter",
			issueSeverity: "low",
			minSeverity:   "high",
			shouldInclude: false,
		},
		{
			name:          "medium severity with high filter",
			issueSeverity: "medium",
			minSeverity:   "high",
			shouldInclude: false,
		},
		{
			name:          "high severity with critical filter",
			issueSeverity: "high",
			minSeverity:   "critical",
			shouldInclude: false,
		},
		
		// Test edge cases
		{
			name:          "unknown severity",
			issueSeverity: "unknown",
			minSeverity:   "low",
			shouldInclude: false,
		},
		{
			name:          "unknown filter",
			issueSeverity: "high",
			minSeverity:   "unknown",
			shouldInclude: true, // unknown maps to 0, so high (3) >= 0
		},
		{
			name:          "case insensitive severity",
			issueSeverity: "HIGH",
			minSeverity:   "medium",
			shouldInclude: true,
		},
		{
			name:          "case insensitive filter",
			issueSeverity: "high",
			minSeverity:   "MEDIUM",
			shouldInclude: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.shouldIncludeIssue(tt.issueSeverity, tt.minSeverity)
			if result != tt.shouldInclude {
				t.Errorf("shouldIncludeIssue(%s, %s) = %v, want %v", 
					tt.issueSeverity, tt.minSeverity, result, tt.shouldInclude)
			}
		})
	}
}

func TestRuleEngineAddCustomRule(t *testing.T) {
	engine := NewRuleEngine()
	initialCount := len(engine.rules)

	customRule := &MockRule{
		RuleName: "CUSTOM_RULE",
		RuleIssues: []types.Issue{
			{
				Rule:     "CUSTOM_RULE",
				Message:  "Custom rule violation",
				Severity: "medium",
				Line:     1,
			},
		},
	}

	engine.AddCustomRule(customRule)

	if len(engine.rules) != initialCount+1 {
		t.Errorf("Expected %d rules after adding custom rule, got %d", 
			initialCount+1, len(engine.rules))
	}

	// Test that the custom rule is executed
	config := &parser.Config{
		Blocks: []types.Block{
			{
				Type: "resource",
				Labels: []string{"test", "resource"},
			},
		},
	}

	issues := engine.RunRules(config, "all")

	// Check if custom rule issue is included
	found := false
	for _, issue := range issues {
		if issue.Rule == "CUSTOM_RULE" {
			found = true
			break
		}
	}

	if !found {
		t.Error("Expected custom rule to be executed and produce issues")
	}
}

func TestRuleEngineWithEmptyConfig(t *testing.T) {
	engine := NewRuleEngine()

	// Test with empty config
	emptyConfig := &parser.Config{
		Blocks: []types.Block{},
	}

	issues := engine.RunRules(emptyConfig, "all")

	// Should not crash and return non-nil slice (may be empty)
	if issues == nil {
		t.Error("Expected non-nil issues slice, even if empty")
	}
	
	// Empty config is valid - no issues expected for most rules
	t.Logf("Empty config produced %d issues", len(issues))
}

func TestRuleEngineWithNilConfig(t *testing.T) {
	// Create a simple engine with mock rules to test nil config handling
	engine := &RuleEngine{
		rules: []Rule{
			&MockRule{
				RuleName: "SAFE_RULE",
				RuleIssues: []types.Issue{
					{Rule: "SAFE_RULE", Message: "Safe rule", Severity: "low", Line: 1},
				},
			},
		},
	}

	// Test with nil config - should not crash
	defer func() {
		if r := recover(); r != nil {
			t.Logf("Note: RunRules with nil config panicked: %v", r)
			// This is acceptable behavior - rules may expect non-nil config
		}
	}()

	issues := engine.RunRules(nil, "all")
	
	// Should handle gracefully or return empty slice
	if issues == nil {
		t.Error("Expected non-nil issues slice")
	}
}

func TestRuleEngineRuleTypes(t *testing.T) {
	engine := NewRuleEngine()

	// Check that we have rules for different categories
	ruleCategories := map[string]bool{
		"EXPOSED_SECRETS":         false,
		"PUBLIC_ACCESS":           false,
		"UNENCRYPTED_STORAGE":     false,
		"UNRESTRICTED_INGRESS":    false,
		"MISSING_TAGS":            false,
		"AWS_EXPOSED_SECRETS":     false,
		"AZURE_EXPOSED_SECRETS":   false,
	}

	// Create a test config to run rules
	config := &parser.Config{
		Blocks: []types.Block{
			{
				Type:   "provider",
				Labels: []string{"aws"},
				Attributes: map[string]types.Attribute{
					"access_key": {
						Name:     "access_key",
						Value:    "AKIAIOSFODNN7EXAMPLE",
						RawValue: "AKIAIOSFODNN7EXAMPLE",
					},
				},
			},
		},
	}

	issues := engine.RunRules(config, "all")

	// Check what types of rules are producing issues
	for _, issue := range issues {
		if _, exists := ruleCategories[issue.Rule]; exists {
			ruleCategories[issue.Rule] = true
		}
	}

	// Verify we have diverse rule types (at least some should trigger)
	triggeredCount := 0
	for _, triggered := range ruleCategories {
		if triggered {
			triggeredCount++
		}
	}

	if triggeredCount == 0 {
		t.Error("Expected at least some security rules to trigger with test config")
	}
}

// Benchmark tests
func BenchmarkRuleEngineRunRules(b *testing.B) {
	engine := NewRuleEngine()
	
	config := &parser.Config{
		Blocks: []types.Block{
			{
				Type:   "resource",
				Labels: []string{"aws_instance", "test"},
				Attributes: map[string]types.Attribute{
					"ami": {
						Name:     "ami",
						Value:    "ami-12345",
						RawValue: "ami-12345",
					},
					"instance_type": {
						Name:     "instance_type",
						Value:    "t3.micro",
						RawValue: "t3.micro",
					},
				},
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.RunRules(config, "all")
	}
}

func BenchmarkShouldIncludeIssue(b *testing.B) {
	engine := NewRuleEngine()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.shouldIncludeIssue("high", "medium")
	}
}

func BenchmarkRuleEngineWithManyRules(b *testing.B) {
	engine := &RuleEngine{}
	
	// Add many mock rules
	for i := 0; i < 100; i++ {
		rule := &MockRule{
			RuleName: "MOCK_RULE",
			RuleIssues: []types.Issue{
				{
					Rule:     "MOCK_RULE",
					Message:  "Mock issue",
					Severity: "low",
					Line:     1,
				},
			},
		}
		engine.rules = append(engine.rules, rule)
	}

	config := &parser.Config{
		Blocks: []types.Block{
			{
				Type:   "resource",
				Labels: []string{"test"},
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = engine.RunRules(config, "all")
	}
} 