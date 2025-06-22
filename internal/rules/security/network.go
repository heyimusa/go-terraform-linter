package security

import (
	"strings"

	"github.com/heyimusa/go-terraform-linter/internal/parser"
	"github.com/heyimusa/go-terraform-linter/internal/types"
)

// PublicAccessRule detects public access configurations
type PublicAccessRule struct{}

func (r *PublicAccessRule) GetName() string { return "PUBLIC_ACCESS" }
func (r *PublicAccessRule) GetDescription() string { return "Detects public access configurations" }
func (r *PublicAccessRule) GetSeverity() string { return "high" }
func (r *PublicAccessRule) GetCategory() string { return "network" }
func (r *PublicAccessRule) GetProvider() string { return "multi" }
func (r *PublicAccessRule) GetTags() []string { return []string{"security", "public-access"} }
func (r *PublicAccessRule) GetVersion() string { return "1.0.0" }

func (r *PublicAccessRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) > 0 {
			resourceType := block.Labels[0]
			
			// Check for public access in various resources
			if strings.Contains(resourceType, "aws_s3_bucket") {
				if attr, exists := block.Attributes["acl"]; exists {
					if acl, ok := attr.Value.(string); ok && acl == "public-read" {
						issues = append(issues, types.Issue{
							Rule:        r.GetName(),
							Message:     "S3 bucket has public read access",
							Description: "Public read access allows anyone to read bucket contents",
							Severity:    "high",
							Line:        attr.Range.Start.Line,
						})
					}
				}
			}

			if strings.Contains(resourceType, "aws_security_group") {
				for _, nestedBlock := range block.Blocks {
					if nestedBlock.Type == "ingress" {
						if cidr, exists := nestedBlock.Attributes["cidr_blocks"]; exists {
							if cidrStr, ok := cidr.Value.(string); ok && cidrStr == "0.0.0.0/0" {
								issues = append(issues, types.Issue{
									Rule:        r.GetName(),
									Message:     "Security group allows access from anywhere",
									Description: "0.0.0.0/0 allows access from any IP address",
									Severity:    "high",
									Line:        cidr.Range.Start.Line,
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

// OpenPortsRule detects sensitive ports open to the world
type OpenPortsRule struct{}

func (r *OpenPortsRule) GetName() string { return "OPEN_PORTS" }
func (r *OpenPortsRule) GetDescription() string { return "Detects sensitive ports open to the world" }
func (r *OpenPortsRule) GetSeverity() string { return "high" }
func (r *OpenPortsRule) GetCategory() string { return "network" }
func (r *OpenPortsRule) GetProvider() string { return "multi" }
func (r *OpenPortsRule) GetTags() []string { return []string{"security", "network", "ports"} }
func (r *OpenPortsRule) GetVersion() string { return "1.0.0" }

func (r *OpenPortsRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) > 0 &&
			strings.Contains(block.Labels[0], "security_group") {
			for _, nested := range block.Blocks {
				if nested.Type == "ingress" {
					cidr, hasCidr := nested.Attributes["cidr_blocks"]
					fromPort, hasFrom := nested.Attributes["from_port"]
					if hasCidr && hasFrom {
						if cidrStr, ok := cidr.Value.(string); ok && cidrStr == "0.0.0.0/0" {
							if from, ok := fromPort.Value.(int); ok {
								if from == 22 || from == 3389 || from == 80 || from == 443 {
									issues = append(issues, types.Issue{
										Rule:        r.GetName(),
										Message:     "Sensitive port open to the world",
										Description: "Port opened to 0.0.0.0/0 (world). Restrict access to trusted IPs.",
										Severity:    "high",
										Line:        fromPort.Range.Start.Line,
									})
								}
							}
						}
					}
				}
			}
		}
	}
	return issues
}

// UnrestrictedIngressRule detects security groups with overly permissive rules
type UnrestrictedIngressRule struct{}

func (r *UnrestrictedIngressRule) GetName() string { return "UNRESTRICTED_INGRESS" }

func (r *UnrestrictedIngressRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) > 0 {
			resourceType := block.Labels[0]
			
			if strings.Contains(resourceType, "aws_security_group") {
				for _, nestedBlock := range block.Blocks {
					if nestedBlock.Type == "ingress" {
						if port, exists := nestedBlock.Attributes["from_port"]; exists {
							if fromPort, ok := port.Value.(int); ok && fromPort == 0 {
								issues = append(issues, types.Issue{
									Rule:        r.GetName(),
									Message:     "Security group allows all ports",
									Description: "Opening all ports (0) is a security risk",
									Severity:    "high",
									Line:        port.Range.Start.Line,
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