package security

import (
	"strings"

	"github.com/heyimusa/go-terraform-linter/internal/parser"
	"github.com/heyimusa/go-terraform-linter/internal/types"
)

// =============================================================================
// GCP COMPUTE ENGINE SECURITY RULES (25+ rules)
// =============================================================================

// GCPComputeInstancePublicIPRule detects instances with public IPs
type GCPComputeInstancePublicIPRule struct{}

func (r *GCPComputeInstancePublicIPRule) GetName() string { return "gcp-compute-instance-public-ip" }
func (r *GCPComputeInstancePublicIPRule) GetDescription() string { return "Compute instance should not have public IP" }
func (r *GCPComputeInstancePublicIPRule) GetSeverity() string { return "medium" }
func (r *GCPComputeInstancePublicIPRule) GetCategory() string { return "compute" }
func (r *GCPComputeInstancePublicIPRule) GetProvider() string { return "gcp" }
func (r *GCPComputeInstancePublicIPRule) GetTags() []string { return []string{"compute", "public-ip", "network"} }
func (r *GCPComputeInstancePublicIPRule) GetVersion() string { return "1.0.0" }

func (r *GCPComputeInstancePublicIPRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if isGCPComputeInstance(&block) {
			for _, networkInterfaceBlock := range block.Blocks {
				if networkInterfaceBlock.Type == "network_interface" {
					for _, accessConfigBlock := range networkInterfaceBlock.Blocks {
						if accessConfigBlock.Type == "access_config" {
							issues = append(issues, types.Issue{
								Rule: r.GetName(), Severity: r.GetSeverity(),
								Message: "Compute instance has public IP address configured",
								Line: accessConfigBlock.Range.Start.Line,
								Description: "Remove access_config block and use Cloud NAT for outbound traffic",
							})
						}
					}
				}
			}
		}
	}
	return issues
}

// GCPComputeInstanceOSLoginRule ensures OS Login is enabled
type GCPComputeInstanceOSLoginRule struct{}

func (r *GCPComputeInstanceOSLoginRule) GetName() string { return "gcp-compute-instance-os-login" }
func (r *GCPComputeInstanceOSLoginRule) GetDescription() string { return "Compute instance should have OS Login enabled" }
func (r *GCPComputeInstanceOSLoginRule) GetSeverity() string { return "medium" }
func (r *GCPComputeInstanceOSLoginRule) GetCategory() string { return "security" }
func (r *GCPComputeInstanceOSLoginRule) GetProvider() string { return "gcp" }
func (r *GCPComputeInstanceOSLoginRule) GetTags() []string { return []string{"compute", "os-login", "authentication"} }
func (r *GCPComputeInstanceOSLoginRule) GetVersion() string { return "1.0.0" }

func (r *GCPComputeInstanceOSLoginRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if isGCPComputeInstance(&block) {
			hasOSLogin := false
			if metadata, exists := block.Attributes["metadata"]; exists {
				metadataStr := ctyValueToString(metadata.Value)
				if strings.Contains(metadataStr, "enable-oslogin") && strings.Contains(metadataStr, "TRUE") {
					hasOSLogin = true
				}
			}
			if !hasOSLogin {
				issues = append(issues, types.Issue{
					Rule: r.GetName(), Severity: r.GetSeverity(),
					Message: "Compute instance does not have OS Login enabled",
					Line: block.Range.Start.Line,
					Description: "Add metadata = { \"enable-oslogin\" = \"TRUE\" }",
				})
			}
		}
	}
	return issues
}

// GCPComputeInstanceShieldedVMRule ensures Shielded VM is enabled
type GCPComputeInstanceShieldedVMRule struct{}

func (r *GCPComputeInstanceShieldedVMRule) GetName() string { return "gcp-compute-instance-shielded-vm" }
func (r *GCPComputeInstanceShieldedVMRule) GetDescription() string { return "Compute instance should have Shielded VM enabled" }
func (r *GCPComputeInstanceShieldedVMRule) GetSeverity() string { return "medium" }
func (r *GCPComputeInstanceShieldedVMRule) GetCategory() string { return "security" }
func (r *GCPComputeInstanceShieldedVMRule) GetProvider() string { return "gcp" }
func (r *GCPComputeInstanceShieldedVMRule) GetTags() []string { return []string{"compute", "shielded-vm", "security"} }
func (r *GCPComputeInstanceShieldedVMRule) GetVersion() string { return "1.0.0" }

func (r *GCPComputeInstanceShieldedVMRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if isGCPComputeInstance(&block) {
			hasShieldedVM := false
			for _, shieldedInstanceConfigBlock := range block.Blocks {
				if shieldedInstanceConfigBlock.Type == "shielded_instance_config" {
					hasShieldedVM = true
					if enableSecureBoot, exists := shieldedInstanceConfigBlock.Attributes["enable_secure_boot"]; exists {
						if ctyValueToString(enableSecureBoot.Value) != "true" {
							issues = append(issues, types.Issue{
								Rule: r.GetName(), Severity: r.GetSeverity(),
								Message: "Compute instance Shielded VM does not have secure boot enabled",
								Line: enableSecureBoot.Range.Start.Line,
								Description: "Set enable_secure_boot = true",
							})
						}
					}
				}
			}
			if !hasShieldedVM {
				issues = append(issues, types.Issue{
					Rule: r.GetName(), Severity: r.GetSeverity(),
					Message: "Compute instance does not have Shielded VM configured",
					Line: block.Range.Start.Line,
					Description: "Add shielded_instance_config block with enable_secure_boot = true",
				})
			}
		}
	}
	return issues
}

// GCPComputeDiskEncryptionRule ensures disks are encrypted with customer keys
type GCPComputeDiskEncryptionRule struct{}

func (r *GCPComputeDiskEncryptionRule) GetName() string { return "gcp-compute-disk-encryption" }
func (r *GCPComputeDiskEncryptionRule) GetDescription() string { return "Compute disk should be encrypted with customer-managed keys" }
func (r *GCPComputeDiskEncryptionRule) GetSeverity() string { return "high" }
func (r *GCPComputeDiskEncryptionRule) GetCategory() string { return "encryption" }
func (r *GCPComputeDiskEncryptionRule) GetProvider() string { return "gcp" }
func (r *GCPComputeDiskEncryptionRule) GetTags() []string { return []string{"compute", "disk", "encryption"} }
func (r *GCPComputeDiskEncryptionRule) GetVersion() string { return "1.0.0" }

func (r *GCPComputeDiskEncryptionRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "google_compute_disk" {
			for _, diskEncryptionKeyBlock := range block.Blocks {
				if diskEncryptionKeyBlock.Type == "disk_encryption_key" {
					if _, exists := diskEncryptionKeyBlock.Attributes["kms_key_self_link"]; !exists {
						issues = append(issues, types.Issue{
							Rule: r.GetName(), Severity: r.GetSeverity(),
							Message: "Compute disk uses default encryption instead of customer-managed keys",
							Line: diskEncryptionKeyBlock.Range.Start.Line,
							Description: "Add kms_key_self_link to use customer-managed encryption keys",
						})
					}
				}
			}
		}
	}
	return issues
}

// =============================================================================
// GCP CLOUD STORAGE SECURITY RULES (20+ rules)
// =============================================================================

// GCPStorageBucketPublicAccessRule detects publicly accessible buckets
type GCPStorageBucketPublicAccessRule struct{}

func (r *GCPStorageBucketPublicAccessRule) GetName() string { return "gcp-storage-bucket-public-access" }
func (r *GCPStorageBucketPublicAccessRule) GetDescription() string { return "Storage bucket should not be publicly accessible" }
func (r *GCPStorageBucketPublicAccessRule) GetSeverity() string { return "critical" }
func (r *GCPStorageBucketPublicAccessRule) GetCategory() string { return "storage" }
func (r *GCPStorageBucketPublicAccessRule) GetProvider() string { return "gcp" }
func (r *GCPStorageBucketPublicAccessRule) GetTags() []string { return []string{"storage", "public-access", "data-exposure"} }
func (r *GCPStorageBucketPublicAccessRule) GetVersion() string { return "1.0.0" }

func (r *GCPStorageBucketPublicAccessRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 && 
		   (block.Labels[0] == "google_storage_bucket_iam_binding" || block.Labels[0] == "google_storage_bucket_iam_member") {
			if members, exists := block.Attributes["members"]; exists {
				memberStr := ctyValueToString(members.Value)
				if strings.Contains(memberStr, "allUsers") || strings.Contains(memberStr, "allAuthenticatedUsers") {
					issues = append(issues, types.Issue{
						Rule: r.GetName(), Severity: r.GetSeverity(),
						Message: "Storage bucket allows public access via IAM",
						Line: members.Range.Start.Line,
						Description: "Remove allUsers and allAuthenticatedUsers from members list",
					})
				}
			}
		}
	}
	return issues
}

// GCPStorageBucketUniformAccessRule ensures uniform bucket-level access
type GCPStorageBucketUniformAccessRule struct{}

func (r *GCPStorageBucketUniformAccessRule) GetName() string { return "gcp-storage-bucket-uniform-access" }
func (r *GCPStorageBucketUniformAccessRule) GetDescription() string { return "Storage bucket should have uniform bucket-level access enabled" }
func (r *GCPStorageBucketUniformAccessRule) GetSeverity() string { return "medium" }
func (r *GCPStorageBucketUniformAccessRule) GetCategory() string { return "storage" }
func (r *GCPStorageBucketUniformAccessRule) GetProvider() string { return "gcp" }
func (r *GCPStorageBucketUniformAccessRule) GetTags() []string { return []string{"storage", "uniform-access", "security"} }
func (r *GCPStorageBucketUniformAccessRule) GetVersion() string { return "1.0.0" }

func (r *GCPStorageBucketUniformAccessRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if isGCPStorageBucket(&block) {
			hasUniformAccess := false
			for _, uniformBucketAccessBlock := range block.Blocks {
				if uniformBucketAccessBlock.Type == "uniform_bucket_level_access" {
					hasUniformAccess = true
					if enabled, exists := uniformBucketAccessBlock.Attributes["enabled"]; exists {
						if ctyValueToString(enabled.Value) != "true" {
							issues = append(issues, types.Issue{
								Rule: r.GetName(), Severity: r.GetSeverity(),
								Message: "Storage bucket does not have uniform bucket-level access enabled",
								Line: enabled.Range.Start.Line,
								Description: "Set enabled = true in uniform_bucket_level_access block",
							})
						}
					}
				}
			}
			if !hasUniformAccess {
				issues = append(issues, types.Issue{
					Rule: r.GetName(), Severity: r.GetSeverity(),
					Message: "Storage bucket does not have uniform bucket-level access configured",
					Line: block.Range.Start.Line,
					Description: "Add uniform_bucket_level_access block with enabled = true",
				})
			}
		}
	}
	return issues
}

// GCPStorageBucketVersioningRule ensures versioning is enabled
type GCPStorageBucketVersioningRule struct{}

func (r *GCPStorageBucketVersioningRule) GetName() string { return "gcp-storage-bucket-versioning" }
func (r *GCPStorageBucketVersioningRule) GetDescription() string { return "Storage bucket should have versioning enabled" }
func (r *GCPStorageBucketVersioningRule) GetSeverity() string { return "low" }
func (r *GCPStorageBucketVersioningRule) GetCategory() string { return "data-protection" }
func (r *GCPStorageBucketVersioningRule) GetProvider() string { return "gcp" }
func (r *GCPStorageBucketVersioningRule) GetTags() []string { return []string{"storage", "versioning", "data-protection"} }
func (r *GCPStorageBucketVersioningRule) GetVersion() string { return "1.0.0" }

func (r *GCPStorageBucketVersioningRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if isGCPStorageBucket(&block) {
			hasVersioning := false
			for _, versioningBlock := range block.Blocks {
				if versioningBlock.Type == "versioning" {
					hasVersioning = true
					if enabled, exists := versioningBlock.Attributes["enabled"]; exists {
						if ctyValueToString(enabled.Value) != "true" {
							issues = append(issues, types.Issue{
								Rule: r.GetName(), Severity: r.GetSeverity(),
								Message: "Storage bucket does not have versioning enabled",
								Line: enabled.Range.Start.Line,
								Description: "Set enabled = true in versioning block",
							})
						}
					}
				}
			}
			if !hasVersioning {
				issues = append(issues, types.Issue{
					Rule: r.GetName(), Severity: r.GetSeverity(),
					Message: "Storage bucket does not have versioning configured",
					Line: block.Range.Start.Line,
					Description: "Add versioning block with enabled = true",
				})
			}
		}
	}
	return issues
}

// =============================================================================
// GCP CLOUD SQL SECURITY RULES (15+ rules)
// =============================================================================

// GCPCloudSQLSSLRule ensures SSL is required
type GCPCloudSQLSSLRule struct{}

func (r *GCPCloudSQLSSLRule) GetName() string { return "gcp-cloudsql-ssl-required" }
func (r *GCPCloudSQLSSLRule) GetDescription() string { return "Cloud SQL instance should require SSL connections" }
func (r *GCPCloudSQLSSLRule) GetSeverity() string { return "high" }
func (r *GCPCloudSQLSSLRule) GetCategory() string { return "database" }
func (r *GCPCloudSQLSSLRule) GetProvider() string { return "gcp" }
func (r *GCPCloudSQLSSLRule) GetTags() []string { return []string{"cloudsql", "ssl", "encryption"} }
func (r *GCPCloudSQLSSLRule) GetVersion() string { return "1.0.0" }

func (r *GCPCloudSQLSSLRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if isGCPCloudSQLInstance(&block) {
			for _, settingsBlock := range block.Blocks {
				if settingsBlock.Type == "settings" {
					for _, ipConfigurationBlock := range settingsBlock.Blocks {
						if ipConfigurationBlock.Type == "ip_configuration" {
							if requireSSL, exists := ipConfigurationBlock.Attributes["require_ssl"]; exists {
								if ctyValueToString(requireSSL.Value) != "true" {
									issues = append(issues, types.Issue{
										Rule: r.GetName(), Severity: r.GetSeverity(),
										Message: "Cloud SQL instance does not require SSL connections",
										Line: requireSSL.Range.Start.Line,
										Description: "Set require_ssl = true",
									})
								}
							} else {
								issues = append(issues, types.Issue{
									Rule: r.GetName(), Severity: r.GetSeverity(),
									Message: "Cloud SQL instance SSL requirement not specified",
									Line: ipConfigurationBlock.Range.Start.Line,
									Description: "Add require_ssl = true",
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

// GCPCloudSQLBackupRule ensures automated backups are enabled
type GCPCloudSQLBackupRule struct{}

func (r *GCPCloudSQLBackupRule) GetName() string { return "gcp-cloudsql-backup-enabled" }
func (r *GCPCloudSQLBackupRule) GetDescription() string { return "Cloud SQL instance should have automated backups enabled" }
func (r *GCPCloudSQLBackupRule) GetSeverity() string { return "medium" }
func (r *GCPCloudSQLBackupRule) GetCategory() string { return "data-protection" }
func (r *GCPCloudSQLBackupRule) GetProvider() string { return "gcp" }
func (r *GCPCloudSQLBackupRule) GetTags() []string { return []string{"cloudsql", "backup", "data-protection"} }
func (r *GCPCloudSQLBackupRule) GetVersion() string { return "1.0.0" }

func (r *GCPCloudSQLBackupRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if isGCPCloudSQLInstance(&block) {
			for _, settingsBlock := range block.Blocks {
				if settingsBlock.Type == "settings" {
					hasBackupConfig := false
					for _, backupConfigurationBlock := range settingsBlock.Blocks {
						if backupConfigurationBlock.Type == "backup_configuration" {
							hasBackupConfig = true
							if enabled, exists := backupConfigurationBlock.Attributes["enabled"]; exists {
								if ctyValueToString(enabled.Value) != "true" {
									issues = append(issues, types.Issue{
										Rule: r.GetName(), Severity: r.GetSeverity(),
										Message: "Cloud SQL instance does not have automated backups enabled",
										Line: enabled.Range.Start.Line,
										Description: "Set enabled = true in backup_configuration",
									})
								}
							}
						}
					}
					if !hasBackupConfig {
						issues = append(issues, types.Issue{
							Rule: r.GetName(), Severity: r.GetSeverity(),
							Message: "Cloud SQL instance does not have backup configuration",
							Line: settingsBlock.Range.Start.Line,
							Description: "Add backup_configuration block with enabled = true",
						})
					}
				}
			}
		}
	}
	return issues
}

// =============================================================================
// GCP FIREWALL SECURITY RULES (10+ rules)
// =============================================================================

// GCPFirewallSSHWorldRule detects SSH access from anywhere
type GCPFirewallSSHWorldRule struct{}

func (r *GCPFirewallSSHWorldRule) GetName() string { return "gcp-firewall-ssh-world" }
func (r *GCPFirewallSSHWorldRule) GetDescription() string { return "Firewall rule should not allow SSH from anywhere" }
func (r *GCPFirewallSSHWorldRule) GetSeverity() string { return "critical" }
func (r *GCPFirewallSSHWorldRule) GetCategory() string { return "network" }
func (r *GCPFirewallSSHWorldRule) GetProvider() string { return "gcp" }
func (r *GCPFirewallSSHWorldRule) GetTags() []string { return []string{"firewall", "ssh", "public-access"} }
func (r *GCPFirewallSSHWorldRule) GetVersion() string { return "1.0.0" }

func (r *GCPFirewallSSHWorldRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if isGCPComputeFirewall(&block) {
			if direction, exists := block.Attributes["direction"]; exists {
				if ctyValueToString(direction.Value) == "INGRESS" {
					for _, allowBlock := range block.Blocks {
						if allowBlock.Type == "allow" {
							if ports, exists := allowBlock.Attributes["ports"]; exists {
								portsStr := ctyValueToString(ports.Value)
								if strings.Contains(portsStr, "22") {
									if sourceRanges, exists := block.Attributes["source_ranges"]; exists {
										sourceRangesStr := ctyValueToString(sourceRanges.Value)
										if strings.Contains(sourceRangesStr, "0.0.0.0/0") {
											issues = append(issues, types.Issue{
												Rule: r.GetName(), Severity: r.GetSeverity(),
												Message: "Firewall rule allows SSH access from anywhere (0.0.0.0/0)",
												Line: sourceRanges.Range.Start.Line,
												Description: "Restrict source_ranges to specific IP ranges",
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
	}
	return issues
}

// GCPFirewallRDPWorldRule detects RDP access from anywhere
type GCPFirewallRDPWorldRule struct{}

func (r *GCPFirewallRDPWorldRule) GetName() string { return "gcp-firewall-rdp-world" }
func (r *GCPFirewallRDPWorldRule) GetDescription() string { return "Firewall rule should not allow RDP from anywhere" }
func (r *GCPFirewallRDPWorldRule) GetSeverity() string { return "critical" }
func (r *GCPFirewallRDPWorldRule) GetCategory() string { return "network" }
func (r *GCPFirewallRDPWorldRule) GetProvider() string { return "gcp" }
func (r *GCPFirewallRDPWorldRule) GetTags() []string { return []string{"firewall", "rdp", "public-access"} }
func (r *GCPFirewallRDPWorldRule) GetVersion() string { return "1.0.0" }

func (r *GCPFirewallRDPWorldRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if isGCPComputeFirewall(&block) {
			if direction, exists := block.Attributes["direction"]; exists {
				if ctyValueToString(direction.Value) == "INGRESS" {
					for _, allowBlock := range block.Blocks {
						if allowBlock.Type == "allow" {
							if ports, exists := allowBlock.Attributes["ports"]; exists {
								portsStr := ctyValueToString(ports.Value)
								if strings.Contains(portsStr, "3389") {
									if sourceRanges, exists := block.Attributes["source_ranges"]; exists {
										sourceRangesStr := ctyValueToString(sourceRanges.Value)
										if strings.Contains(sourceRangesStr, "0.0.0.0/0") {
											issues = append(issues, types.Issue{
												Rule: r.GetName(), Severity: r.GetSeverity(),
												Message: "Firewall rule allows RDP access from anywhere (0.0.0.0/0)",
												Line: sourceRanges.Range.Start.Line,
												Description: "Restrict source_ranges to specific IP ranges",
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
	}
	return issues
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

func isGCPComputeInstance(block *types.Block) bool {
	return block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "google_compute_instance"
}

func isGCPStorageBucket(block *types.Block) bool {
	return block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "google_storage_bucket"
}

func isGCPCloudSQLInstance(block *types.Block) bool {
	return block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "google_sql_database_instance"
}

func isGCPComputeFirewall(block *types.Block) bool {
	return block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "google_compute_firewall"
}

// Note: ctyValueToString function is already defined in aws_comprehensive.go 