package custom

import (
	"github.com/heyimusa/go-terraform-linter/internal/parser"
	"github.com/heyimusa/go-terraform-linter/internal/types"
)

// CustomRule struct for YAML/JSON-based rules
// Only simple attribute checks for now
// Example:
// - resource_type: aws_s3_bucket
//   attribute: acl
//   equals: public-read
//   message: S3 bucket is public
//   severity: high

type CustomRule struct {
	ResourceType string      `yaml:"resource_type" json:"resource_type"`
	Attribute    string      `yaml:"attribute" json:"attribute"`
	Equals       interface{} `yaml:"equals" json:"equals"`
	Message      string      `yaml:"message" json:"message"`
	Severity     string      `yaml:"severity" json:"severity"`
}

// CustomRule implements rules.Rule
func (cr CustomRule) GetName() string {
	return "CUSTOM_RULE: " + cr.ResourceType + "." + cr.Attribute
}

func (cr CustomRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) > 0 && block.Labels[0] == cr.ResourceType {
			if attr, ok := block.Attributes[cr.Attribute]; ok {
				if attr.Value == cr.Equals {
					issues = append(issues, types.Issue{
						Rule:        cr.GetName(),
						Message:     cr.Message,
						Description: cr.Message,
						Severity:    cr.Severity,
						Line:        attr.Range.Start.Line,
					})
				}
			}
		}
	}
	return issues
} 