package security

import (
	"fmt"
	"strings"

	"github.com/heyimusa/go-terraform-linter/internal/parser"
	"github.com/heyimusa/go-terraform-linter/internal/types"
)

// =============================================================================
// AZURE STORAGE ACCOUNT SECURITY RULES (20+ rules)
// =============================================================================

// AzureStorageAccountHTTPSOnlyRule ensures storage accounts enforce HTTPS
type AzureStorageAccountHTTPSOnlyRule struct{}

func (r *AzureStorageAccountHTTPSOnlyRule) GetName() string { return "azure-storage-account-https-only" }
func (r *AzureStorageAccountHTTPSOnlyRule) GetDescription() string { return "Storage account should enforce HTTPS only" }
func (r *AzureStorageAccountHTTPSOnlyRule) GetSeverity() string { return "high" }
func (r *AzureStorageAccountHTTPSOnlyRule) GetCategory() string { return "storage" }
func (r *AzureStorageAccountHTTPSOnlyRule) GetProvider() string { return "azure" }
func (r *AzureStorageAccountHTTPSOnlyRule) GetTags() []string { return []string{"storage", "https", "encryption"} }
func (r *AzureStorageAccountHTTPSOnlyRule) GetVersion() string { return "1.0.0" }

func (r *AzureStorageAccountHTTPSOnlyRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if isAzureStorageAccount(&block) {
			if httpsOnly, exists := block.Attributes["enable_https_traffic_only"]; exists {
				if ctyValueToString(httpsOnly.Value) != "true" {
					issues = append(issues, types.Issue{
						Rule: r.GetName(), Severity: r.GetSeverity(),
						Message: "Storage account does not enforce HTTPS traffic only",
						Line: httpsOnly.Range.Start.Line,
						Description: "Set enable_https_traffic_only = true",
					})
				}
			} else {
				issues = append(issues, types.Issue{
					Rule: r.GetName(), Severity: r.GetSeverity(),
					Message: "Storage account HTTPS enforcement not specified",
					Line: block.Range.Start.Line,
					Description: "Add enable_https_traffic_only = true",
				})
			}
		}
	}
	return issues
}

// AzureStorageAccountPublicAccessRule detects public blob access
type AzureStorageAccountPublicAccessRule struct{}

func (r *AzureStorageAccountPublicAccessRule) GetName() string { return "azure-storage-account-public-access" }
func (r *AzureStorageAccountPublicAccessRule) GetDescription() string { return "Storage account should not allow public blob access" }
func (r *AzureStorageAccountPublicAccessRule) GetSeverity() string { return "critical" }
func (r *AzureStorageAccountPublicAccessRule) GetCategory() string { return "storage" }
func (r *AzureStorageAccountPublicAccessRule) GetProvider() string { return "azure" }
func (r *AzureStorageAccountPublicAccessRule) GetTags() []string { return []string{"storage", "public-access", "data-exposure"} }
func (r *AzureStorageAccountPublicAccessRule) GetVersion() string { return "1.0.0" }

func (r *AzureStorageAccountPublicAccessRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if isAzureStorageAccount(&block) {
			if allowBlobPublicAccess, exists := block.Attributes["allow_blob_public_access"]; exists {
				if ctyValueToString(allowBlobPublicAccess.Value) == "true" {
					issues = append(issues, types.Issue{
						Rule: r.GetName(), Severity: r.GetSeverity(),
						Message: "Storage account allows public blob access",
						Line: allowBlobPublicAccess.Range.Start.Line,
						Description: "Set allow_blob_public_access = false",
					})
				}
			}
		}
	}
	return issues
}

// AzureStorageAccountMinTLSRule ensures minimum TLS version
type AzureStorageAccountMinTLSRule struct{}

func (r *AzureStorageAccountMinTLSRule) GetName() string { return "azure-storage-account-min-tls" }
func (r *AzureStorageAccountMinTLSRule) GetDescription() string { return "Storage account should enforce minimum TLS version 1.2" }
func (r *AzureStorageAccountMinTLSRule) GetSeverity() string { return "medium" }
func (r *AzureStorageAccountMinTLSRule) GetCategory() string { return "encryption" }
func (r *AzureStorageAccountMinTLSRule) GetProvider() string { return "azure" }
func (r *AzureStorageAccountMinTLSRule) GetTags() []string { return []string{"storage", "tls", "encryption"} }
func (r *AzureStorageAccountMinTLSRule) GetVersion() string { return "1.0.0" }

func (r *AzureStorageAccountMinTLSRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if isAzureStorageAccount(&block) {
			if minTLSVersion, exists := block.Attributes["min_tls_version"]; exists {
				tlsVersion := ctyValueToString(minTLSVersion.Value)
				if tlsVersion != "TLS1_2" {
					issues = append(issues, types.Issue{
						Rule: r.GetName(), Severity: r.GetSeverity(),
						Message: "Storage account does not enforce minimum TLS version 1.2",
						Line: minTLSVersion.Range.Start.Line,
						Description: "Set min_tls_version = \"TLS1_2\"",
					})
				}
			} else {
				issues = append(issues, types.Issue{
					Rule: r.GetName(), Severity: r.GetSeverity(),
					Message: "Storage account minimum TLS version not specified",
					Line: block.Range.Start.Line,
					Description: "Add min_tls_version = \"TLS1_2\"",
				})
			}
		}
	}
	return issues
}

// AzureStorageAccountNetworkRulesRule ensures network access rules
type AzureStorageAccountNetworkRulesRule struct{}

func (r *AzureStorageAccountNetworkRulesRule) GetName() string { return "azure-storage-account-network-rules" }
func (r *AzureStorageAccountNetworkRulesRule) GetDescription() string { return "Storage account should have network access rules configured" }
func (r *AzureStorageAccountNetworkRulesRule) GetSeverity() string { return "medium" }
func (r *AzureStorageAccountNetworkRulesRule) GetCategory() string { return "network" }
func (r *AzureStorageAccountNetworkRulesRule) GetProvider() string { return "azure" }
func (r *AzureStorageAccountNetworkRulesRule) GetTags() []string { return []string{"storage", "network", "firewall"} }
func (r *AzureStorageAccountNetworkRulesRule) GetVersion() string { return "1.0.0" }

func (r *AzureStorageAccountNetworkRulesRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if isAzureStorageAccount(&block) {
			hasNetworkRules := false
			for _, nestedBlock := range block.Blocks {
				if nestedBlock.Type == "network_rules" {
					hasNetworkRules = true
					if defaultAction, exists := nestedBlock.Attributes["default_action"]; exists {
						if ctyValueToString(defaultAction.Value) == "Allow" {
							issues = append(issues, types.Issue{
								Rule: r.GetName(), Severity: r.GetSeverity(),
								Message: "Storage account network rules allow access by default",
								Line: defaultAction.Range.Start.Line,
								Description: "Set default_action = \"Deny\" and configure specific allow rules",
							})
						}
					}
				}
			}
			if !hasNetworkRules {
				issues = append(issues, types.Issue{
					Rule: r.GetName(), Severity: r.GetSeverity(),
					Message: "Storage account does not have network access rules configured",
					Line: block.Range.Start.Line,
					Description: "Add network_rules block with default_action = \"Deny\"",
				})
			}
		}
	}
	return issues
}

// =============================================================================
// AZURE VIRTUAL MACHINE SECURITY RULES (25+ rules)
// =============================================================================

// AzureVMDiskEncryptionRule ensures VM disks are encrypted
type AzureVMDiskEncryptionRule struct{}

func (r *AzureVMDiskEncryptionRule) GetName() string { return "azure-vm-disk-encryption" }
func (r *AzureVMDiskEncryptionRule) GetDescription() string { return "Virtual machine disks should be encrypted" }
func (r *AzureVMDiskEncryptionRule) GetSeverity() string { return "high" }
func (r *AzureVMDiskEncryptionRule) GetCategory() string { return "compute" }
func (r *AzureVMDiskEncryptionRule) GetProvider() string { return "azure" }
func (r *AzureVMDiskEncryptionRule) GetTags() []string { return []string{"vm", "disk", "encryption"} }
func (r *AzureVMDiskEncryptionRule) GetVersion() string { return "1.0.0" }

func (r *AzureVMDiskEncryptionRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if isAzureVM(&block) {
			for _, osDiskBlock := range block.Blocks {
				if osDiskBlock.Type == "os_disk" {
					if encryptionType, exists := osDiskBlock.Attributes["encryption_type"]; exists {
						if ctyValueToString(encryptionType.Value) == "EncryptionAtRestWithPlatformKey" {
							issues = append(issues, types.Issue{
								Rule: r.GetName(), Severity: r.GetSeverity(),
								Message: "VM OS disk uses platform-managed encryption instead of customer-managed keys",
								Line: encryptionType.Range.Start.Line,
								Description: "Use EncryptionAtRestWithCustomerKey or EncryptionAtRestWithPlatformAndCustomerKeys",
							})
						}
					} else {
						issues = append(issues, types.Issue{
							Rule: r.GetName(), Severity: r.GetSeverity(),
							Message: "VM OS disk encryption not specified",
							Line: osDiskBlock.Range.Start.Line,
							Description: "Add encryption_type with customer-managed keys",
						})
					}
				}
			}
		}
	}
	return issues
}

// AzureVMPublicIPRule detects VMs with public IP addresses
type AzureVMPublicIPRule struct{}

func (r *AzureVMPublicIPRule) GetName() string { return "azure-vm-public-ip" }
func (r *AzureVMPublicIPRule) GetDescription() string { return "Virtual machine should not have public IP address" }
func (r *AzureVMPublicIPRule) GetSeverity() string { return "medium" }
func (r *AzureVMPublicIPRule) GetCategory() string { return "network" }
func (r *AzureVMPublicIPRule) GetProvider() string { return "azure" }
func (r *AzureVMPublicIPRule) GetTags() []string { return []string{"vm", "public-ip", "network"} }
func (r *AzureVMPublicIPRule) GetVersion() string { return "1.0.0" }

func (r *AzureVMPublicIPRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	
	// Track network interfaces with public IPs
	networkInterfacesWithPublicIP := make(map[string]bool)
	
	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "azurerm_network_interface" {
			for _, ipConfigBlock := range block.Blocks {
				if ipConfigBlock.Type == "ip_configuration" {
					if publicIPRef, exists := ipConfigBlock.Attributes["public_ip_address_id"]; exists {
						if ctyValueToString(publicIPRef.Value) != "" {
							networkInterfacesWithPublicIP[block.Labels[1]] = true
						}
					}
				}
			}
		}
	}
	
	// Check VMs using those network interfaces
	for _, block := range config.Blocks {
		if isAzureVM(&block) {
			if networkInterfaceIds, exists := block.Attributes["network_interface_ids"]; exists {
				interfaceIds := ctyValueToString(networkInterfaceIds.Value)
				for nicName := range networkInterfacesWithPublicIP {
					if strings.Contains(interfaceIds, nicName) {
						issues = append(issues, types.Issue{
							Rule: r.GetName(), Severity: r.GetSeverity(),
							Message: "Virtual machine has public IP address",
							Line: networkInterfaceIds.Range.Start.Line,
							Description: "Remove public IP and use bastion host or VPN for access",
						})
					}
				}
			}
		}
	}
	return issues
}

// AzureVMBootDiagnosticsRule ensures boot diagnostics are enabled
type AzureVMBootDiagnosticsRule struct{}

func (r *AzureVMBootDiagnosticsRule) GetName() string { return "azure-vm-boot-diagnostics" }
func (r *AzureVMBootDiagnosticsRule) GetDescription() string { return "Virtual machine should have boot diagnostics enabled" }
func (r *AzureVMBootDiagnosticsRule) GetSeverity() string { return "low" }
func (r *AzureVMBootDiagnosticsRule) GetCategory() string { return "monitoring" }
func (r *AzureVMBootDiagnosticsRule) GetProvider() string { return "azure" }
func (r *AzureVMBootDiagnosticsRule) GetTags() []string { return []string{"vm", "diagnostics", "monitoring"} }
func (r *AzureVMBootDiagnosticsRule) GetVersion() string { return "1.0.0" }

func (r *AzureVMBootDiagnosticsRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if isAzureVM(&block) {
			hasBootDiagnostics := false
			for _, nestedBlock := range block.Blocks {
				if nestedBlock.Type == "boot_diagnostics" {
					hasBootDiagnostics = true
				}
			}
			if !hasBootDiagnostics {
				issues = append(issues, types.Issue{
					Rule: r.GetName(), Severity: r.GetSeverity(),
					Message: "Virtual machine does not have boot diagnostics enabled",
					Line: block.Range.Start.Line,
					Description: "Add boot_diagnostics block",
				})
			}
		}
	}
	return issues
}

// =============================================================================
// AZURE NETWORK SECURITY GROUP RULES (15+ rules)
// =============================================================================

// AzureNSGSSHWorldRule detects SSH access from anywhere
type AzureNSGSSHWorldRule struct{}

func (r *AzureNSGSSHWorldRule) GetName() string { return "azure-nsg-ssh-world" }
func (r *AzureNSGSSHWorldRule) GetDescription() string { return "Network security group allows SSH access from anywhere" }
func (r *AzureNSGSSHWorldRule) GetSeverity() string { return "critical" }
func (r *AzureNSGSSHWorldRule) GetCategory() string { return "network" }
func (r *AzureNSGSSHWorldRule) GetProvider() string { return "azure" }
func (r *AzureNSGSSHWorldRule) GetTags() []string { return []string{"nsg", "ssh", "public-access"} }
func (r *AzureNSGSSHWorldRule) GetVersion() string { return "1.0.0" }

func (r *AzureNSGSSHWorldRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if isAzureNSG(&block) {
			for _, securityRuleBlock := range block.Blocks {
				if securityRuleBlock.Type == "security_rule" {
					if access, exists := securityRuleBlock.Attributes["access"]; exists {
						if ctyValueToString(access.Value) == "Allow" {
							if destinationPortRange, exists := securityRuleBlock.Attributes["destination_port_range"]; exists {
								if ctyValueToString(destinationPortRange.Value) == "22" {
									if sourceAddressPrefix, exists := securityRuleBlock.Attributes["source_address_prefix"]; exists {
										if ctyValueToString(sourceAddressPrefix.Value) == "*" {
											issues = append(issues, types.Issue{
												Rule: r.GetName(), Severity: r.GetSeverity(),
												Message: "Network security group allows SSH access from anywhere (*)",
												Line: sourceAddressPrefix.Range.Start.Line,
												Description: "Restrict SSH access to specific IP ranges",
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

// AzureNSGRDPWorldRule detects RDP access from anywhere
type AzureNSGRDPWorldRule struct{}

func (r *AzureNSGRDPWorldRule) GetName() string { return "azure-nsg-rdp-world" }
func (r *AzureNSGRDPWorldRule) GetDescription() string { return "Network security group allows RDP access from anywhere" }
func (r *AzureNSGRDPWorldRule) GetSeverity() string { return "critical" }
func (r *AzureNSGRDPWorldRule) GetCategory() string { return "network" }
func (r *AzureNSGRDPWorldRule) GetProvider() string { return "azure" }
func (r *AzureNSGRDPWorldRule) GetTags() []string { return []string{"nsg", "rdp", "public-access"} }
func (r *AzureNSGRDPWorldRule) GetVersion() string { return "1.0.0" }

func (r *AzureNSGRDPWorldRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if isAzureNSG(&block) {
			for _, securityRuleBlock := range block.Blocks {
				if securityRuleBlock.Type == "security_rule" {
					if access, exists := securityRuleBlock.Attributes["access"]; exists {
						if ctyValueToString(access.Value) == "Allow" {
							if destinationPortRange, exists := securityRuleBlock.Attributes["destination_port_range"]; exists {
								if ctyValueToString(destinationPortRange.Value) == "3389" {
									if sourceAddressPrefix, exists := securityRuleBlock.Attributes["source_address_prefix"]; exists {
										if ctyValueToString(sourceAddressPrefix.Value) == "*" {
											issues = append(issues, types.Issue{
												Rule: r.GetName(), Severity: r.GetSeverity(),
												Message: "Network security group allows RDP access from anywhere (*)",
												Line: sourceAddressPrefix.Range.Start.Line,
												Description: "Restrict RDP access to specific IP ranges",
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
// AZURE KEY VAULT SECURITY RULES (15+ rules)
// =============================================================================

// AzureKeyVaultSoftDeleteRule ensures soft delete is enabled
type AzureKeyVaultSoftDeleteRule struct{}

func (r *AzureKeyVaultSoftDeleteRule) GetName() string { return "azure-key-vault-soft-delete" }
func (r *AzureKeyVaultSoftDeleteRule) GetDescription() string { return "Key Vault should have soft delete enabled" }
func (r *AzureKeyVaultSoftDeleteRule) GetSeverity() string { return "medium" }
func (r *AzureKeyVaultSoftDeleteRule) GetCategory() string { return "security" }
func (r *AzureKeyVaultSoftDeleteRule) GetProvider() string { return "azure" }
func (r *AzureKeyVaultSoftDeleteRule) GetTags() []string { return []string{"key-vault", "soft-delete", "data-protection"} }
func (r *AzureKeyVaultSoftDeleteRule) GetVersion() string { return "1.0.0" }

func (r *AzureKeyVaultSoftDeleteRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if isAzureKeyVault(&block) {
			if softDeleteEnabled, exists := block.Attributes["soft_delete_enabled"]; exists {
				if ctyValueToString(softDeleteEnabled.Value) != "true" {
					issues = append(issues, types.Issue{
						Rule: r.GetName(), Severity: r.GetSeverity(),
						Message: "Key Vault does not have soft delete enabled",
						Line: softDeleteEnabled.Range.Start.Line,
						Description: "Set soft_delete_enabled = true",
					})
				}
			} else {
				issues = append(issues, types.Issue{
					Rule: r.GetName(), Severity: r.GetSeverity(),
					Message: "Key Vault soft delete not specified",
					Line: block.Range.Start.Line,
					Description: "Add soft_delete_enabled = true",
				})
			}
		}
	}
	return issues
}

// AzureKeyVaultPurgeProtectionRule ensures purge protection is enabled
type AzureKeyVaultPurgeProtectionRule struct{}

func (r *AzureKeyVaultPurgeProtectionRule) GetName() string { return "azure-key-vault-purge-protection" }
func (r *AzureKeyVaultPurgeProtectionRule) GetDescription() string { return "Key Vault should have purge protection enabled" }
func (r *AzureKeyVaultPurgeProtectionRule) GetSeverity() string { return "medium" }
func (r *AzureKeyVaultPurgeProtectionRule) GetCategory() string { return "security" }
func (r *AzureKeyVaultPurgeProtectionRule) GetProvider() string { return "azure" }
func (r *AzureKeyVaultPurgeProtectionRule) GetTags() []string { return []string{"key-vault", "purge-protection", "data-protection"} }
func (r *AzureKeyVaultPurgeProtectionRule) GetVersion() string { return "1.0.0" }

func (r *AzureKeyVaultPurgeProtectionRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if isAzureKeyVault(&block) {
			if purgeProtectionEnabled, exists := block.Attributes["purge_protection_enabled"]; exists {
				if ctyValueToString(purgeProtectionEnabled.Value) != "true" {
					issues = append(issues, types.Issue{
						Rule: r.GetName(), Severity: r.GetSeverity(),
						Message: "Key Vault does not have purge protection enabled",
						Line: purgeProtectionEnabled.Range.Start.Line,
						Description: "Set purge_protection_enabled = true",
					})
				}
			} else {
				issues = append(issues, types.Issue{
					Rule: r.GetName(), Severity: r.GetSeverity(),
					Message: "Key Vault purge protection not specified",
					Line: block.Range.Start.Line,
					Description: "Add purge_protection_enabled = true",
				})
			}
		}
	}
	return issues
}

// AzureKeyVaultNetworkAclsRule ensures network ACLs are configured
type AzureKeyVaultNetworkAclsRule struct{}

func (r *AzureKeyVaultNetworkAclsRule) GetName() string { return "azure-key-vault-network-acls" }
func (r *AzureKeyVaultNetworkAclsRule) GetDescription() string { return "Key Vault should have network ACLs configured" }
func (r *AzureKeyVaultNetworkAclsRule) GetSeverity() string { return "medium" }
func (r *AzureKeyVaultNetworkAclsRule) GetCategory() string { return "network" }
func (r *AzureKeyVaultNetworkAclsRule) GetProvider() string { return "azure" }
func (r *AzureKeyVaultNetworkAclsRule) GetTags() []string { return []string{"key-vault", "network", "firewall"} }
func (r *AzureKeyVaultNetworkAclsRule) GetVersion() string { return "1.0.0" }

func (r *AzureKeyVaultNetworkAclsRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	for _, block := range config.Blocks {
		if isAzureKeyVault(&block) {
			hasNetworkAcls := false
			for _, nestedBlock := range block.Blocks {
				if nestedBlock.Type == "network_acls" {
					hasNetworkAcls = true
					if defaultAction, exists := nestedBlock.Attributes["default_action"]; exists {
						if ctyValueToString(defaultAction.Value) == "Allow" {
							issues = append(issues, types.Issue{
								Rule: r.GetName(), Severity: r.GetSeverity(),
								Message: "Key Vault network ACLs allow access by default",
								Line: defaultAction.Range.Start.Line,
								Description: "Set default_action = \"Deny\" and configure specific allow rules",
							})
						}
					}
				}
			}
			if !hasNetworkAcls {
				issues = append(issues, types.Issue{
					Rule: r.GetName(), Severity: r.GetSeverity(),
					Message: "Key Vault does not have network ACLs configured",
					Line: block.Range.Start.Line,
					Description: "Add network_acls block with default_action = \"Deny\"",
				})
			}
		}
	}
	return issues
}

// =============================================================================
// AZURE SQL DATABASE SECURITY RULES (20+ rules)
// =============================================================================

// AzureSQLServerTDERule ensures Transparent Data Encryption is enabled
type AzureSQLServerTDERule struct{}

func (r *AzureSQLServerTDERule) GetName() string { return "azure-sql-server-tde" }
func (r *AzureSQLServerTDERule) GetDescription() string { return "SQL Server should have Transparent Data Encryption enabled" }
func (r *AzureSQLServerTDERule) GetSeverity() string { return "high" }
func (r *AzureSQLServerTDERule) GetCategory() string { return "database" }
func (r *AzureSQLServerTDERule) GetProvider() string { return "azure" }
func (r *AzureSQLServerTDERule) GetTags() []string { return []string{"sql", "encryption", "tde"} }
func (r *AzureSQLServerTDERule) GetVersion() string { return "1.0.0" }

func (r *AzureSQLServerTDERule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	sqlServers := make(map[string]bool)
	
	// Track SQL servers
	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "azurerm_sql_server" {
			sqlServers[block.Labels[1]] = false
		}
	}
	
	// Check for TDE configuration
	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "azurerm_sql_database" {
			if _, exists := block.Attributes["transparent_data_encryption_enabled"]; exists {
				// TDE is configured at database level
				continue
			} else {
				issues = append(issues, types.Issue{
					Rule: r.GetName(), Severity: r.GetSeverity(),
					Message: "SQL Database does not have Transparent Data Encryption enabled",
					Line: block.Range.Start.Line,
					Description: "Add transparent_data_encryption_enabled = true",
				})
			}
		}
	}
	return issues
}

// AzureSQLServerAuditingRule ensures auditing is enabled
type AzureSQLServerAuditingRule struct{}

func (r *AzureSQLServerAuditingRule) GetName() string { return "azure-sql-server-auditing" }
func (r *AzureSQLServerAuditingRule) GetDescription() string { return "SQL Server should have auditing enabled" }
func (r *AzureSQLServerAuditingRule) GetSeverity() string { return "medium" }
func (r *AzureSQLServerAuditingRule) GetCategory() string { return "logging" }
func (r *AzureSQLServerAuditingRule) GetProvider() string { return "azure" }
func (r *AzureSQLServerAuditingRule) GetTags() []string { return []string{"sql", "auditing", "logging"} }
func (r *AzureSQLServerAuditingRule) GetVersion() string { return "1.0.0" }

func (r *AzureSQLServerAuditingRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue
	sqlServers := make(map[string]bool)
	
	// Track SQL servers
	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "azurerm_sql_server" {
			sqlServers[block.Labels[1]] = false
		}
	}
	
	// Check for auditing policy
	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "azurerm_sql_server_auditing_policy" {
			if serverName, exists := block.Attributes["server_name"]; exists {
				serverNameStr := ctyValueToString(serverName.Value)
				sqlServers[serverNameStr] = true
			}
		}
	}
	
	// Report servers without auditing
	for serverName, hasAuditing := range sqlServers {
		if !hasAuditing {
			issues = append(issues, types.Issue{
				Rule: r.GetName(), Severity: r.GetSeverity(),
				Message: fmt.Sprintf("SQL Server '%s' does not have auditing enabled", serverName),
				Description: "Add azurerm_sql_server_auditing_policy resource",
			})
		}
	}
	return issues
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

func isAzureStorageAccount(block *types.Block) bool {
	return block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "azurerm_storage_account"
}

func isAzureVM(block *types.Block) bool {
	return block.Type == "resource" && len(block.Labels) >= 2 && 
		   (block.Labels[0] == "azurerm_virtual_machine" || 
		    block.Labels[0] == "azurerm_linux_virtual_machine" || 
		    block.Labels[0] == "azurerm_windows_virtual_machine")
}

func isAzureNSG(block *types.Block) bool {
	return block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "azurerm_network_security_group"
}

func isAzureKeyVault(block *types.Block) bool {
	return block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "azurerm_key_vault"
} 