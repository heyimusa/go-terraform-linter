package security

import (
	"fmt"
	"strings"

	"github.com/hashicorp/go-cty/cty"
	"github.com/heyimusa/go-terraform-linter/internal/parser"
	"github.com/heyimusa/go-terraform-linter/internal/types"
)

// GCP Security Rules Implementation

// GCPPublicStorageRule detects publicly accessible GCS buckets
type GCPPublicStorageRule struct{}

func (r *GCPPublicStorageRule) GetName() string { return "GCP_PUBLIC_STORAGE" }
func (r *GCPPublicStorageRule) GetDescription() string {
	return "Detects Google Cloud Storage buckets with public access"
}
func (r *GCPPublicStorageRule) GetSeverity() string { return "critical" }
func (r *GCPPublicStorageRule) GetCategory() string { return "storage" }
func (r *GCPPublicStorageRule) GetProvider() string { return "gcp" }
func (r *GCPPublicStorageRule) GetTags() []string { return []string{"security", "storage", "public-access"} }
func (r *GCPPublicStorageRule) GetVersion() string { return "1.0.0" }

func (r *GCPPublicStorageRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 {
			resourceType := block.Labels[0]

			// Check GCS bucket IAM bindings for public access
			if resourceType == "google_storage_bucket_iam_binding" || resourceType == "google_storage_bucket_iam_member" {
				if members, exists := block.Attributes["members"]; exists {
					memberStr := ctyValueToString(members.Value)
					if strings.Contains(memberStr, "allUsers") || strings.Contains(memberStr, "allAuthenticatedUsers") {
						issues = append(issues, types.Issue{
							Rule:        r.GetName(),
							Message:     "GCS bucket allows public access",
							Description: "Storage buckets should not be publicly accessible",
							Severity:    r.GetSeverity(),
							Line:        members.Range.Start.Line,
						})
					}
				}
			}

			// Check GCS bucket uniform bucket-level access
			if resourceType == "google_storage_bucket" {
				if uniformBucketAccess, exists := block.Attributes["uniform_bucket_level_access"]; exists {
					if !strings.Contains(ctyValueToString(uniformBucketAccess.Value), "true") {
						issues = append(issues, types.Issue{
							Rule:        r.GetName(),
							Message:     "GCS bucket does not have uniform bucket-level access enabled",
							Description: "Enable uniform bucket-level access for better security",
							Severity:    "medium",
							Line:        uniformBucketAccess.Range.Start.Line,
						})
					}
				}
			}
		}
	}

	return issues
}

// GCPUnencryptedStorageRule detects unencrypted GCP storage resources
type GCPUnencryptedStorageRule struct{}

func (r *GCPUnencryptedStorageRule) GetName() string { return "GCP_UNENCRYPTED_STORAGE" }
func (r *GCPUnencryptedStorageRule) GetDescription() string {
	return "Detects unencrypted storage resources in GCP"
}
func (r *GCPUnencryptedStorageRule) GetSeverity() string { return "high" }
func (r *GCPUnencryptedStorageRule) GetCategory() string { return "encryption" }
func (r *GCPUnencryptedStorageRule) GetProvider() string { return "gcp" }
func (r *GCPUnencryptedStorageRule) GetTags() []string { return []string{"security", "encryption", "storage"} }
func (r *GCPUnencryptedStorageRule) GetVersion() string { return "1.0.0" }

func (r *GCPUnencryptedStorageRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 {
			resourceType := block.Labels[0]

			// Check Compute Engine disk encryption
			if resourceType == "google_compute_disk" {
				if _, exists := block.Attributes["disk_encryption_key"]; !exists {
					issues = append(issues, types.Issue{
						Rule:        r.GetName(),
						Message:     "Compute Engine disk is not encrypted with customer-managed key",
						Description: "Use customer-managed encryption keys for better security",
						Severity:    "medium",
						Line:        block.Range.Start.Line,
					})
				}
			}

			// Check Cloud SQL instance encryption
			if resourceType == "google_sql_database_instance" {
				encryptionFound := false
				for _, nestedBlock := range block.Blocks {
					if nestedBlock.Type == "settings" {
						for _, settingsBlock := range nestedBlock.Blocks {
							if settingsBlock.Type == "database_flags" {
								if name, exists := settingsBlock.Attributes["name"]; exists {
									if ctyValueToString(name.Value) == "cloudsql.enable_pgaudit" {
										encryptionFound = true
									}
								}
							}
						}
					}
				}
				if !encryptionFound {
					issues = append(issues, types.Issue{
						Rule:        r.GetName(),
						Message:     "Cloud SQL instance may not have proper encryption configured",
						Description: "Ensure Cloud SQL instances have encryption at rest enabled",
						Severity:    r.GetSeverity(),
						Line:        block.Range.Start.Line,
					})
				}
			}
		}
	}

	return issues
}

// GCPOpenFirewallRule detects overly permissive firewall rules
type GCPOpenFirewallRule struct{}

func (r *GCPOpenFirewallRule) GetName() string { return "GCP_OPEN_FIREWALL" }
func (r *GCPOpenFirewallRule) GetDescription() string {
	return "Detects overly permissive GCP firewall rules"
}
func (r *GCPOpenFirewallRule) GetSeverity() string { return "high" }
func (r *GCPUnencryptedStorageRule) GetCategory() string { return "network" }
func (r *GCPOpenFirewallRule) GetProvider() string { return "gcp" }
func (r *GCPOpenFirewallRule) GetTags() []string { return []string{"security", "network", "firewall"} }
func (r *GCPOpenFirewallRule) GetVersion() string { return "1.0.0" }

func (r *GCPOpenFirewallRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "google_compute_firewall" {
			// Check source ranges
			if sourceRanges, exists := block.Attributes["source_ranges"]; exists {
				rangeStr := ctyValueToString(sourceRanges.Value)
				if strings.Contains(rangeStr, "0.0.0.0/0") {
					// Check if it's allowing dangerous ports
					dangerousPorts := []string{"22", "3389", "1433", "3306", "5432", "6379", "27017"}
					
					for _, nestedBlock := range block.Blocks {
						if nestedBlock.Type == "allow" {
							if ports, exists := nestedBlock.Attributes["ports"]; exists {
								portStr := ctyValueToString(ports.Value)
								for _, dangerousPort := range dangerousPorts {
									if strings.Contains(portStr, dangerousPort) {
										issues = append(issues, types.Issue{
											Rule:        r.GetName(),
											Message:     fmt.Sprintf("Firewall rule allows access to dangerous port %s from anywhere", dangerousPort),
											Description: "Restrict firewall rules to specific IP ranges",
											Severity:    r.GetSeverity(),
											Line:        sourceRanges.Range.Start.Line,
										})
									}
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

// GCPIAMOverprivilegedRule detects overprivileged IAM roles
type GCPIAMOverprivilegedRule struct{}

func (r *GCPIAMOverprivilegedRule) GetName() string { return "GCP_IAM_OVERPRIVILEGED" }
func (r *GCPIAMOverprivilegedRule) GetDescription() string {
	return "Detects overprivileged IAM roles and bindings in GCP"
}
func (r *GCPIAMOverprivilegedRule) GetSeverity() string { return "high" }
func (r *GCPIAMOverprivilegedRule) GetCategory() string { return "iam" }
func (r *GCPIAMOverprivilegedRule) GetProvider() string { return "gcp" }
func (r *GCPIAMOverprivilegedRule) GetTags() []string { return []string{"security", "iam", "permissions"} }
func (r *GCPIAMOverprivilegedRule) GetVersion() string { return "1.0.0" }

func (r *GCPIAMOverprivilegedRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	dangerousRoles := []string{
		"roles/owner",
		"roles/editor",
		"roles/iam.securityAdmin",
		"roles/resourcemanager.organizationAdmin",
		"roles/billing.admin",
	}

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 {
			resourceType := block.Labels[0]

			if resourceType == "google_project_iam_binding" || resourceType == "google_project_iam_member" {
				if role, exists := block.Attributes["role"]; exists {
					roleStr := ctyValueToString(role.Value)
					for _, dangerousRole := range dangerousRoles {
						if roleStr == dangerousRole {
							issues = append(issues, types.Issue{
								Rule:        r.GetName(),
								Message:     fmt.Sprintf("Overprivileged IAM role assigned: %s", roleStr),
								Description: "Use least privilege principle and assign minimal required permissions",
								Severity:    r.GetSeverity(),
								Line:        role.Range.Start.Line,
							})
						}
					}
				}
			}
		}
	}

	return issues
}

// GCPPublicComputeInstanceRule detects compute instances with public IPs
type GCPPublicComputeInstanceRule struct{}

func (r *GCPPublicComputeInstanceRule) GetName() string { return "GCP_PUBLIC_COMPUTE_INSTANCE" }
func (r *GCPPublicComputeInstanceRule) GetDescription() string {
	return "Detects compute instances with public IP addresses"
}
func (r *GCPPublicComputeInstanceRule) GetSeverity() string { return "medium" }
func (r *GCPPublicComputeInstanceRule) GetCategory() string { return "network" }
func (r *GCPPublicComputeInstanceRule) GetProvider() string { return "gcp" }
func (r *GCPPublicComputeInstanceRule) GetTags() []string { return []string{"security", "network", "compute"} }
func (r *GCPPublicComputeInstanceRule) GetVersion() string { return "1.0.0" }

func (r *GCPPublicComputeInstanceRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "google_compute_instance" {
			for _, nestedBlock := range block.Blocks {
				if nestedBlock.Type == "network_interface" {
					for _, accessConfigBlock := range nestedBlock.Blocks {
						if accessConfigBlock.Type == "access_config" {
							// If access_config block exists, it typically means public IP
							issues = append(issues, types.Issue{
								Rule:        r.GetName(),
								Message:     "Compute instance has public IP address",
								Description: "Consider using private IPs and NAT gateway for better security",
								Severity:    r.GetSeverity(),
								Line:        accessConfigBlock.Range.Start.Line,
							})
						}
					}
				}
			}
		}
	}

	return issues
}

// GCPCloudSQLPublicIPRule detects Cloud SQL instances with public IPs
type GCPCloudSQLPublicIPRule struct{}

func (r *GCPCloudSQLPublicIPRule) GetName() string { return "GCP_CLOUDSQL_PUBLIC_IP" }
func (r *GCPCloudSQLPublicIPRule) GetDescription() string {
	return "Detects Cloud SQL instances with public IP addresses"
}
func (r *GCPCloudSQLPublicIPRule) GetSeverity() string { return "high" }
func (r *GCPCloudSQLPublicIPRule) GetCategory() string { return "database" }
func (r *GCPCloudSQLPublicIPRule) GetProvider() string { return "gcp" }
func (r *GCPCloudSQLPublicIPRule) GetTags() []string { return []string{"security", "database", "network"} }
func (r *GCPCloudSQLPublicIPRule) GetVersion() string { return "1.0.0" }

func (r *GCPCloudSQLPublicIPRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "google_sql_database_instance" {
			for _, nestedBlock := range block.Blocks {
				if nestedBlock.Type == "settings" {
					for _, settingsBlock := range nestedBlock.Blocks {
						if settingsBlock.Type == "ip_configuration" {
							if ipv4Enabled, exists := settingsBlock.Attributes["ipv4_enabled"]; exists {
								if strings.Contains(ctyValueToString(ipv4Enabled.Value), "true") {
									issues = append(issues, types.Issue{
										Rule:        r.GetName(),
										Message:     "Cloud SQL instance has public IP enabled",
										Description: "Use private IPs for Cloud SQL instances to reduce attack surface",
										Severity:    r.GetSeverity(),
										Line:        ipv4Enabled.Range.Start.Line,
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

// GCPKMSKeyRotationRule detects KMS keys without automatic rotation
type GCPKMSKeyRotationRule struct{}

func (r *GCPKMSKeyRotationRule) GetName() string { return "GCP_KMS_KEY_ROTATION" }
func (r *GCPKMSKeyRotationRule) GetDescription() string {
	return "Detects KMS keys without automatic rotation enabled"
}
func (r *GCPKMSKeyRotationRule) GetSeverity() string { return "medium" }
func (r *GCPKMSKeyRotationRule) GetCategory() string { return "encryption" }
func (r *GCPKMSKeyRotationRule) GetProvider() string { return "gcp" }
func (r *GCPKMSKeyRotationRule) GetTags() []string { return []string{"security", "encryption", "kms"} }
func (r *GCPKMSKeyRotationRule) GetVersion() string { return "1.0.0" }

func (r *GCPKMSKeyRotationRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "google_kms_crypto_key" {
			if rotationPeriod, exists := block.Attributes["rotation_period"]; exists {
				// Check if rotation period is reasonable (not too long)
				rotationStr := ctyValueToString(rotationPeriod.Value)
				if rotationStr == "" {
					issues = append(issues, types.Issue{
						Rule:        r.GetName(),
						Message:     "KMS key does not have automatic rotation configured",
						Description: "Enable automatic key rotation for better security",
						Severity:    r.GetSeverity(),
						Line:        block.Range.Start.Line,
					})
				}
			} else {
				issues = append(issues, types.Issue{
					Rule:        r.GetName(),
					Message:     "KMS key does not have automatic rotation configured",
					Description: "Enable automatic key rotation for better security",
					Severity:    r.GetSeverity(),
					Line:        block.Range.Start.Line,
				})
			}
		}
	}

	return issues
}

// GCPLoggingDisabledRule detects resources without proper logging
type GCPLoggingDisabledRule struct{}

func (r *GCPLoggingDisabledRule) GetName() string { return "GCP_LOGGING_DISABLED" }
func (r *GCPLoggingDisabledRule) GetDescription() string {
	return "Detects GCP resources without proper audit logging enabled"
}
func (r *GCPLoggingDisabledRule) GetSeverity() string { return "medium" }
func (r *GCPLoggingDisabledRule) GetCategory() string { return "logging" }
func (r *GCPLoggingDisabledRule) GetProvider() string { return "gcp" }
func (r *GCPLoggingDisabledRule) GetTags() []string { return []string{"security", "logging", "audit"} }
func (r *GCPLoggingDisabledRule) GetVersion() string { return "1.0.0" }

func (r *GCPLoggingDisabledRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 {
			resourceType := block.Labels[0]

			// Check if GCS bucket has logging enabled
			if resourceType == "google_storage_bucket" {
				loggingFound := false
				for _, nestedBlock := range block.Blocks {
					if nestedBlock.Type == "logging" {
						loggingFound = true
						break
					}
				}
				if !loggingFound {
					issues = append(issues, types.Issue{
						Rule:        r.GetName(),
						Message:     "GCS bucket does not have access logging enabled",
						Description: "Enable access logging for audit and security monitoring",
						Severity:    r.GetSeverity(),
						Line:        block.Range.Start.Line,
					})
				}
			}
		}
	}

	return issues
} 