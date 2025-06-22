package security

import (
	"strings"

	"github.com/heyimusa/go-terraform-linter/internal/parser"
	"github.com/heyimusa/go-terraform-linter/internal/types"
)

// UnencryptedStorageRule detects unencrypted storage resources
type UnencryptedStorageRule struct{}

func (r *UnencryptedStorageRule) GetName() string { return "UNENCRYPTED_STORAGE" }
func (r *UnencryptedStorageRule) GetDescription() string { return "Detects unencrypted storage resources" }
func (r *UnencryptedStorageRule) GetSeverity() string { return "high" }
func (r *UnencryptedStorageRule) GetCategory() string { return "storage" }
func (r *UnencryptedStorageRule) GetProvider() string { return "aws" }
func (r *UnencryptedStorageRule) GetTags() []string { return []string{"security", "storage", "encryption"} }
func (r *UnencryptedStorageRule) GetVersion() string { return "1.0.0" }

func (r *UnencryptedStorageRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) > 0 {
			resourceType := block.Labels[0]
			
			if strings.Contains(resourceType, "aws_ebs_volume") {
				if encrypted, exists := block.Attributes["encrypted"]; exists {
					if enc, ok := encrypted.Value.(bool); ok && !enc {
						issues = append(issues, types.Issue{
							Rule:        r.GetName(),
							Message:     "EBS volume is not encrypted",
							Description: "Unencrypted EBS volumes can expose sensitive data",
							Severity:    "high",
							Line:        encrypted.Range.Start.Line,
						})
					}
				} else {
					// No encrypted attribute means unencrypted by default
					issues = append(issues, types.Issue{
						Rule:        r.GetName(),
						Message:     "EBS volume encryption not specified",
						Description: "EBS volumes should be encrypted by default",
						Severity:    "medium",
						Line:        block.Range.Start.Line,
					})
				}
			}
		}
	}

	return issues
}

// EncryptionComplianceRule detects missing encryption for compliance
type EncryptionComplianceRule struct{}

func (r *EncryptionComplianceRule) GetName() string { return "ENCRYPTION_COMPLIANCE" }
func (r *EncryptionComplianceRule) GetDescription() string { return "Detects missing encryption for compliance" }
func (r *EncryptionComplianceRule) GetSeverity() string { return "critical" }
func (r *EncryptionComplianceRule) GetCategory() string { return "compliance" }
func (r *EncryptionComplianceRule) GetProvider() string { return "aws" }
func (r *EncryptionComplianceRule) GetTags() []string { return []string{"security", "compliance", "encryption"} }
func (r *EncryptionComplianceRule) GetVersion() string { return "1.0.0" }

func (r *EncryptionComplianceRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) > 0 {
			resourceType := block.Labels[0]
			if resourceType == "aws_db_instance" || resourceType == "aws_ebs_volume" || resourceType == "aws_rds_cluster" {
				if encrypted, exists := block.Attributes["encrypted"]; exists {
					if enc, ok := encrypted.Value.(bool); ok && !enc {
						issues = append(issues, types.Issue{
							Rule:        r.GetName(),
							Message:     "Encryption is not enabled",
							Description: "Enable encryption for compliance (HIPAA, SOC2, PCI-DSS)",
							Severity:    "critical",
							Line:        encrypted.Range.Start.Line,
						})
					}
				} else {
					issues = append(issues, types.Issue{
						Rule:        r.GetName(),
						Message:     "Encryption attribute missing",
						Description: "Enable encryption for compliance (HIPAA, SOC2, PCI-DSS)",
						Severity:    "critical",
						Line:        block.Range.Start.Line,
					})
				}
			}
		}
	}
	return issues
} 