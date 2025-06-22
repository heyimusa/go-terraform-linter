package types

import (
	"testing"

	"github.com/hashicorp/hcl/v2"
)

func TestIssue(t *testing.T) {
	tests := []struct {
		name     string
		issue    Issue
		expected Issue
	}{
		{
			name: "valid issue creation",
			issue: Issue{
				Rule:        "TEST_RULE",
				Message:     "Test message",
				Description: "Test description",
				Severity:    "high",
				Line:        10,
			},
			expected: Issue{
				Rule:        "TEST_RULE",
				Message:     "Test message",
				Description: "Test description",
				Severity:    "high",
				Line:        10,
			},
		},
		{
			name: "empty issue",
			issue: Issue{},
			expected: Issue{
				Rule:        "",
				Message:     "",
				Description: "",
				Severity:    "",
				Line:        0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.issue.Rule != tt.expected.Rule {
				t.Errorf("Rule: expected %s, got %s", tt.expected.Rule, tt.issue.Rule)
			}
			if tt.issue.Message != tt.expected.Message {
				t.Errorf("Message: expected %s, got %s", tt.expected.Message, tt.issue.Message)
			}
			if tt.issue.Description != tt.expected.Description {
				t.Errorf("Description: expected %s, got %s", tt.expected.Description, tt.issue.Description)
			}
			if tt.issue.Severity != tt.expected.Severity {
				t.Errorf("Severity: expected %s, got %s", tt.expected.Severity, tt.issue.Severity)
			}
			if tt.issue.Line != tt.expected.Line {
				t.Errorf("Line: expected %d, got %d", tt.expected.Line, tt.issue.Line)
			}
		})
	}
}

func TestBlock(t *testing.T) {
	tests := []struct {
		name     string
		block    Block
		expected Block
	}{
		{
			name: "resource block",
			block: Block{
				Type:   "resource",
				Labels: []string{"aws_instance", "test"},
				Attributes: map[string]Attribute{
					"ami": {
						Name:     "ami",
						Value:    "ami-12345678",
						RawValue: "ami-12345678",
					},
				},
				Blocks: []Block{},
				Range:  hcl.Range{},
			},
			expected: Block{
				Type:   "resource",
				Labels: []string{"aws_instance", "test"},
				Attributes: map[string]Attribute{
					"ami": {
						Name:     "ami",
						Value:    "ami-12345678",
						RawValue: "ami-12345678",
					},
				},
				Blocks: []Block{},
				Range:  hcl.Range{},
			},
		},
		{
			name: "nested blocks",
			block: Block{
				Type:   "terraform",
				Labels: []string{},
				Attributes: map[string]Attribute{},
				Blocks: []Block{
					{
						Type:   "required_providers",
						Labels: []string{},
						Attributes: map[string]Attribute{
							"aws": {
								Name:     "aws",
								Value:    "provider_config",
								RawValue: "provider_config",
							},
						},
						Blocks: []Block{},
						Range:  hcl.Range{},
					},
				},
				Range: hcl.Range{},
			},
			expected: Block{
				Type:   "terraform",
				Labels: []string{},
				Attributes: map[string]Attribute{},
				Blocks: []Block{
					{
						Type:   "required_providers",
						Labels: []string{},
						Attributes: map[string]Attribute{
							"aws": {
								Name:     "aws",
								Value:    "provider_config",
								RawValue: "provider_config",
							},
						},
						Blocks: []Block{},
						Range:  hcl.Range{},
					},
				},
				Range: hcl.Range{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.block.Type != tt.expected.Type {
				t.Errorf("Type: expected %s, got %s", tt.expected.Type, tt.block.Type)
			}
			if len(tt.block.Labels) != len(tt.expected.Labels) {
				t.Errorf("Labels length: expected %d, got %d", len(tt.expected.Labels), len(tt.block.Labels))
			}
			for i, label := range tt.expected.Labels {
				if i < len(tt.block.Labels) && tt.block.Labels[i] != label {
					t.Errorf("Label[%d]: expected %s, got %s", i, label, tt.block.Labels[i])
				}
			}
			if len(tt.block.Attributes) != len(tt.expected.Attributes) {
				t.Errorf("Attributes length: expected %d, got %d", len(tt.expected.Attributes), len(tt.block.Attributes))
			}
			if len(tt.block.Blocks) != len(tt.expected.Blocks) {
				t.Errorf("Blocks length: expected %d, got %d", len(tt.expected.Blocks), len(tt.block.Blocks))
			}
		})
	}
}

func TestAttribute(t *testing.T) {
	tests := []struct {
		name      string
		attribute Attribute
		expected  Attribute
	}{
		{
			name: "string attribute",
			attribute: Attribute{
				Name:     "instance_type",
				Value:    "t3.micro",
				RawValue: "t3.micro",
				Range:    hcl.Range{},
			},
			expected: Attribute{
				Name:     "instance_type",
				Value:    "t3.micro",
				RawValue: "t3.micro",
				Range:    hcl.Range{},
			},
		},
		{
			name: "numeric attribute",
			attribute: Attribute{
				Name:     "count",
				Value:    2,
				RawValue: "2",
				Range:    hcl.Range{},
			},
			expected: Attribute{
				Name:     "count",
				Value:    2,
				RawValue: "2",
				Range:    hcl.Range{},
			},
		},
		{
			name: "boolean attribute",
			attribute: Attribute{
				Name:     "enable_dns_hostnames",
				Value:    true,
				RawValue: "true",
				Range:    hcl.Range{},
			},
			expected: Attribute{
				Name:     "enable_dns_hostnames",
				Value:    true,
				RawValue: "true",
				Range:    hcl.Range{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.attribute.Name != tt.expected.Name {
				t.Errorf("Name: expected %s, got %s", tt.expected.Name, tt.attribute.Name)
			}
			if tt.attribute.Value != tt.expected.Value {
				t.Errorf("Value: expected %v, got %v", tt.expected.Value, tt.attribute.Value)
			}
			if tt.attribute.RawValue != tt.expected.RawValue {
				t.Errorf("RawValue: expected %s, got %s", tt.expected.RawValue, tt.attribute.RawValue)
			}
		})
	}
}

// Benchmark tests for performance
func BenchmarkIssueCreation(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = Issue{
			Rule:        "TEST_RULE",
			Message:     "Test message",
			Description: "Test description",
			Severity:    "high",
			Line:        10,
		}
	}
}

func BenchmarkBlockCreation(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = Block{
			Type:   "resource",
			Labels: []string{"aws_instance", "test"},
			Attributes: map[string]Attribute{
				"ami": {
					Name:     "ami",
					Value:    "ami-12345678",
					RawValue: "ami-12345678",
				},
			},
			Blocks: []Block{},
			Range:  hcl.Range{},
		}
	}
} 