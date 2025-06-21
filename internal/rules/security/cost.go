package security

import (
	"github.com/heyimusa/go-terraform-linter/internal/parser"
	"github.com/heyimusa/go-terraform-linter/internal/types"
)

// CostOptimizationRule detects large/expensive instance types
type CostOptimizationRule struct{}

func (r *CostOptimizationRule) GetName() string { return "COST_OPTIMIZATION" }

func (r *CostOptimizationRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	largeTypes := []string{"m5.4xlarge", "m5.8xlarge", "c5.4xlarge", "c5.9xlarge", "r5.4xlarge", "r5.8xlarge"}
	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) > 0 {
			resourceType := block.Labels[0]
			if resourceType == "aws_instance" {
				if instanceType, exists := block.Attributes["instance_type"]; exists {
					if t, ok := instanceType.Value.(string); ok {
						for _, large := range largeTypes {
							if t == large {
								issues = append(issues, types.Issue{
									Rule:        r.GetName(),
									Message:     "Large instance type used",
									Description: "Consider using smaller instance types for cost savings",
									Severity:    "medium",
									Line:        instanceType.Range.Start.Line,
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