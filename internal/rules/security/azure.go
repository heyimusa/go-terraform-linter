package security

import (
	"strings"

	"github.com/hashicorp/go-cty/cty"
	"github.com/heyimusa/go-terraform-linter/internal/parser"
	"github.com/heyimusa/go-terraform-linter/internal/types"
)

// AzureSecurityRules contains Azure-specific security rules
type AzureSecurityRules struct{}

// AzurePublicAccessRule detects public access configurations in Azure
type AzurePublicAccessRule struct{}

func (r *AzurePublicAccessRule) GetName() string {
	return "AZURE_PUBLIC_ACCESS"
}
func (r *AzurePublicAccessRule) GetCategory() string { return "network" }
func (r *AzurePublicAccessRule) GetProvider() string { return "azure" }
func (r *AzurePublicAccessRule) GetTags() []string { return []string{"security", "azure", "public-access"} }
func (r *AzurePublicAccessRule) GetVersion() string { return "1.0.0" }

func (r *AzurePublicAccessRule) GetDescription() string {
	return "Detects public access configurations in Azure resources"
}

func (r *AzurePublicAccessRule) GetSeverity() string {
	return "high"
}

func (r *AzurePublicAccessRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	for _, block := range config.Blocks {
		// Check Azure Storage Account public access
		if block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "azurerm_storage_account" {
			if publicAccess, exists := block.Attributes["public_network_access_enabled"]; exists {
				value := ctyValueToString(publicAccess.Value)
				rawValue := strings.ToLower(strings.Trim(publicAccess.RawValue, `"`))
				if value == "true" || rawValue == "true" {
					issues = append(issues, types.Issue{
						Rule:        r.GetName(),
						Message:     "Storage account has public network access enabled",
						Description: "Storage accounts should not have public network access enabled for security",
						Severity:    r.GetSeverity(),
						Line:        publicAccess.Range.Start.Line,
					})
				}
			}
		}

		// Check Azure Container Registry public access
		if block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "azurerm_container_registry" {
			if publicAccess, exists := block.Attributes["public_network_access_enabled"]; exists {
				value := ctyValueToString(publicAccess.Value)
				rawValue := strings.ToLower(strings.Trim(publicAccess.RawValue, `"`))
				if value == "true" || rawValue == "true" {
					issues = append(issues, types.Issue{
						Rule:        r.GetName(),
						Message:     "Container registry has public network access enabled",
						Description: "Container registries should not have public network access enabled",
						Severity:    r.GetSeverity(),
						Line:        publicAccess.Range.Start.Line,
					})
				}
			}
		}

		// Check Azure Web App public access
		if block.Type == "resource" && len(block.Labels) >= 2 && 
		   (block.Labels[0] == "azurerm_linux_web_app" || block.Labels[0] == "azurerm_windows_web_app") {
			// Check if public access is not restricted
			if publicAccess, exists := block.Attributes["public_network_access_enabled"]; exists {
				value := ctyValueToString(publicAccess.Value)
				rawValue := strings.ToLower(strings.Trim(publicAccess.RawValue, `"`))
				if value == "true" || rawValue == "true" {
					issues = append(issues, types.Issue{
						Rule:        r.GetName(),
						Message:     "Web app has public network access enabled",
						Description: "Web apps should restrict public network access for security",
						Severity:    r.GetSeverity(),
						Line:        publicAccess.Range.Start.Line,
					})
				}
			}
		}
	}

	return issues
}

// AzureUnencryptedStorageRule detects unencrypted storage in Azure
type AzureUnencryptedStorageRule struct{}

func (r *AzureUnencryptedStorageRule) GetName() string {
	return "AZURE_UNENCRYPTED_STORAGE"
}
func (r *AzureUnencryptedStorageRule) GetCategory() string { return "storage" }
func (r *AzureUnencryptedStorageRule) GetProvider() string { return "azure" }
func (r *AzureUnencryptedStorageRule) GetTags() []string { return []string{"security", "azure", "encryption", "storage"} }
func (r *AzureUnencryptedStorageRule) GetVersion() string { return "1.0.0" }

func (r *AzureUnencryptedStorageRule) GetDescription() string {
	return "Identifies unencrypted storage resources in Azure"
}

func (r *AzureUnencryptedStorageRule) GetSeverity() string {
	return "high"
}

func (r *AzureUnencryptedStorageRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	for _, block := range config.Blocks {
		// Check Azure Storage Account encryption
		if block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "azurerm_storage_account" {
			// Check if encryption block exists (nested block)
			hasEncryptionBlock := false
			for _, nestedBlock := range block.Blocks {
				if nestedBlock.Type == "encryption" {
					hasEncryptionBlock = true
					break
				}
			}
			
			// Check if encryption attribute exists
			if encryptionAttr, exists := block.Attributes["encryption"]; exists {
				value := ctyValueToString(encryptionAttr.Value)
				rawValue := strings.ToLower(strings.Trim(encryptionAttr.RawValue, `"`))
				if value == "false" || rawValue == "false" {
					issues = append(issues, types.Issue{
						Rule:        r.GetName(),
						Message:     "Storage account encryption disabled",
						Description: "Azure storage accounts should be encrypted by default",
						Severity:    r.GetSeverity(),
						Line:        encryptionAttr.Range.Start.Line,
					})
				}
			} else if !hasEncryptionBlock {
				// Only report if neither encryption attribute nor encryption block exists
				issues = append(issues, types.Issue{
					Rule:        r.GetName(),
					Message:     "Storage account encryption not specified",
					Description: "Azure storage accounts should be encrypted by default",
					Severity:    r.GetSeverity(),
					Line:        block.Range.Start.Line,
				})
			}
		}

		// Check Azure Disk encryption
		if block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "azurerm_managed_disk" {
			if _, exists := block.Attributes["encryption_settings"]; !exists {
				issues = append(issues, types.Issue{
					Rule:        r.GetName(),
					Message:     "Managed disk encryption not specified",
					Description: "Azure managed disks should be encrypted by default",
					Severity:    r.GetSeverity(),
					Line:        block.Range.Start.Line,
				})
			}
		}
	}

	return issues
}

// AzureWeakPasswordRule detects weak password configurations in Azure
type AzureWeakPasswordRule struct{}

func (r *AzureWeakPasswordRule) GetName() string {
	return "AZURE_WEAK_PASSWORD"
}
func (r *AzureWeakPasswordRule) GetCategory() string { return "authentication" }
func (r *AzureWeakPasswordRule) GetProvider() string { return "azure" }
func (r *AzureWeakPasswordRule) GetTags() []string { return []string{"security", "azure", "authentication", "password"} }
func (r *AzureWeakPasswordRule) GetVersion() string { return "1.0.0" }

func (r *AzureWeakPasswordRule) GetDescription() string {
	return "Detects weak password configurations in Azure resources"
}

func (r *AzureWeakPasswordRule) GetSeverity() string {
	return "medium"
}

func (r *AzureWeakPasswordRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	for _, block := range config.Blocks {
		// Check Azure SQL Database password
		if block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "azurerm_sql_server" {
			if password, exists := block.Attributes["administrator_login_password"]; exists {
				passStr := ctyValueToString(password.Value)
				if len(passStr) < 8 || strings.Contains(passStr, "password") || strings.Contains(passStr, "123") {
					issues = append(issues, types.Issue{
						Rule:        r.GetName(),
						Message:     "Weak password detected in SQL server",
						Description: "Use strong passwords for database administrators",
						Severity:    r.GetSeverity(),
						Line:        password.Range.Start.Line,
					})
				}
			}
		}
	}

	return issues
}

// AzureMissingTagsRule detects resources without proper tagging
type AzureMissingTagsRule struct{}

func (r *AzureMissingTagsRule) GetName() string {
	return "AZURE_MISSING_TAGS"
}
func (r *AzureMissingTagsRule) GetCategory() string { return "best-practices" }
func (r *AzureMissingTagsRule) GetProvider() string { return "azure" }
func (r *AzureMissingTagsRule) GetTags() []string { return []string{"best-practices", "azure", "tagging"} }
func (r *AzureMissingTagsRule) GetVersion() string { return "1.0.0" }

func (r *AzureMissingTagsRule) GetDescription() string {
	return "Resources without proper tagging in Azure"
}

func (r *AzureMissingTagsRule) GetSeverity() string {
	return "low"
}

func (r *AzureMissingTagsRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 {
			// Check for Azure resources that should have tags
			azureResources := []string{
				"azurerm_virtual_machine",
				"azurerm_storage_account",
				"azurerm_sql_server",
				"azurerm_network_security_group",
				"azurerm_virtual_network",
				"azurerm_subnet",
				"azurerm_public_ip",
				"azurerm_load_balancer",
				"azurerm_app_service",
				"azurerm_container_registry",
			}

			for _, resourceType := range azureResources {
				if block.Labels[0] == resourceType {
					if _, exists := block.Attributes["tags"]; !exists {
						issues = append(issues, types.Issue{
							Rule:        r.GetName(),
							Message:     "Resource missing tags",
							Description: "Azure resources should be tagged for better organization and cost tracking",
							Severity:    r.GetSeverity(),
							Line:        block.Range.Start.Line,
						})
					}
					break
				}
			}
		}
	}

	return issues
}

// AzureExposedSecretsRule detects hardcoded secrets in Azure configurations
type AzureExposedSecretsRule struct{}

func (r *AzureExposedSecretsRule) GetName() string {
	return "AZURE_EXPOSED_SECRETS"
}
func (r *AzureExposedSecretsRule) GetCategory() string { return "security" }
func (r *AzureExposedSecretsRule) GetProvider() string { return "azure" }
func (r *AzureExposedSecretsRule) GetTags() []string { return []string{"security", "azure", "secrets"} }
func (r *AzureExposedSecretsRule) GetVersion() string { return "1.0.0" }

func (r *AzureExposedSecretsRule) GetDescription() string {
	return "Hardcoded secrets in Azure configuration"
}

func (r *AzureExposedSecretsRule) GetSeverity() string {
	return "critical"
}

// Enhanced helper function to recursively extract values from complex cty.Value structures
func extractValuesFromCtyValue(value interface{}) []string {
	var results []string
	
	if ctyVal, ok := value.(cty.Value); ok {
		if ctyVal.Type() == cty.String {
			results = append(results, ctyVal.AsString())
		} else if ctyVal.Type().IsMapType() || ctyVal.Type().IsObjectType() {
			// Recursively extract from maps/objects
			if !ctyVal.IsNull() && ctyVal.IsKnown() {
				it := ctyVal.ElementIterator()
				for it.Next() {
					key, val := it.Element()
					// Extract both key and value
					if key.Type() == cty.String {
						results = append(results, key.AsString())
					}
					if val.Type() == cty.String {
						results = append(results, val.AsString())
					} else {
						// Recursively extract from nested structures
						results = append(results, extractValuesFromCtyValue(val)...)
					}
				}
			}
		} else if ctyVal.Type().IsListType() || ctyVal.Type().IsSetType() || ctyVal.Type().IsTupleType() {
			// Recursively extract from lists/sets/tuples
			if !ctyVal.IsNull() && ctyVal.IsKnown() {
				it := ctyVal.ElementIterator()
				for it.Next() {
					_, val := it.Element()
					results = append(results, extractValuesFromCtyValue(val)...)
				}
			}
		} else {
			// For other types, try to extract from the debug representation
			debugStr := ctyVal.GoString()
			// Look for patterns like "{{{} 83}}" which indicate string values
			if strings.Contains(debugStr, "{{{} 83}}") {
				// This is a complex structure, try to extract values from the debug output
				results = append(results, extractFromDebugString(debugStr)...)
			}
		}
	} else if str, ok := value.(string); ok {
		results = append(results, str)
	}
	
	return results
}

// Helper function to extract values from debug string representation
func extractFromDebugString(debugStr string) []string {
	var results []string
	
	// The debug output shows actual values in a specific format
	// These appear at the end of the debug string after the last "}"
	
	// Find the last occurrence of "}" and extract everything after it
	lastBrace := strings.LastIndex(debugStr, "}")
	if lastBrace != -1 && lastBrace < len(debugStr)-1 {
		valuesPart := debugStr[lastBrace+1:]
		valuesPart = strings.TrimSpace(valuesPart)
		
		// Look for patterns like "map[KEY:VALUE KEY2:VALUE2 ...]"
		if strings.HasPrefix(valuesPart, "map[") && strings.HasSuffix(valuesPart, "]") {
			mapContent := valuesPart[4 : len(valuesPart)-1] // Remove "map[" and "]"
			
			// Parse key-value pairs
			// Split by spaces, but be careful with values that contain spaces
			pairs := parseKeyValuePairs(mapContent)
			for _, pair := range pairs {
				if strings.Contains(pair, ":") {
					parts := strings.SplitN(pair, ":", 2)
					if len(parts) == 2 {
						key := strings.TrimSpace(parts[0])
						value := strings.TrimSpace(parts[1])
						results = append(results, key)
						results = append(results, value)
					}
				}
			}
		}
	}
	
	return results
}

// Helper function to parse key-value pairs from map content
func parseKeyValuePairs(content string) []string {
	var pairs []string
	var current strings.Builder
	inValue := false
	depth := 0
	
	for i, char := range content {
		switch char {
		case ':':
			if !inValue && depth == 0 {
				inValue = true
				current.WriteRune(char)
			} else {
				current.WriteRune(char)
			}
		case ' ':
			if inValue && depth == 0 {
				// Check if this is the end of a value (next character should be a key)
				// Look ahead to see if we're starting a new key
				if i+1 < len(content) {
					remaining := content[i+1:]
					// If the next non-space character sequence looks like a key (contains letters and ends with :)
					nextWord := strings.Fields(remaining)
					if len(nextWord) > 0 && isLikelyKey(nextWord[0]) {
						pairs = append(pairs, current.String())
						current.Reset()
						inValue = false
						continue
					}
				}
				current.WriteRune(char)
			} else if !inValue {
				current.WriteRune(char)
			} else {
				current.WriteRune(char)
			}
		default:
			current.WriteRune(char)
		}
	}
	
	// Add the last pair
	if current.Len() > 0 {
		pairs = append(pairs, current.String())
	}
	
	return pairs
}

// Helper function to check if a string looks like a key
func isLikelyKey(s string) bool {
	// A key is likely if it contains letters and doesn't look like a URL or complex value
	hasLetters := false
	for _, char := range s {
		if (char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z') {
			hasLetters = true
			break
		}
	}
	
	// Keys are usually uppercase and don't contain common value patterns
	return hasLetters && !strings.Contains(s, "://") && !strings.Contains(s, "base64:") && !strings.Contains(s, "@")
}

// Note: ctyValueToString function is already defined in aws_comprehensive.go

// AzureUnrestrictedIngressRule detects overly permissive network security groups
type AzureUnrestrictedIngressRule struct{}

func (r *AzureUnrestrictedIngressRule) GetName() string {
	return "AZURE_UNRESTRICTED_INGRESS"
}
func (r *AzureUnrestrictedIngressRule) GetCategory() string { return "network" }
func (r *AzureUnrestrictedIngressRule) GetProvider() string { return "azure" }
func (r *AzureUnrestrictedIngressRule) GetTags() []string { return []string{"security", "azure", "network", "ingress"} }
func (r *AzureUnrestrictedIngressRule) GetVersion() string { return "1.0.0" }

func (r *AzureUnrestrictedIngressRule) GetDescription() string {
	return "Network security groups with overly permissive rules"
}

func (r *AzureUnrestrictedIngressRule) GetSeverity() string {
	return "high"
}

func (r *AzureUnrestrictedIngressRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "azurerm_network_security_rule" {
			if sourceAddressPrefix, exists := block.Attributes["source_address_prefix"]; exists {
				if ctyValueToString(sourceAddressPrefix.Value) == "*" || ctyValueToString(sourceAddressPrefix.Value) == "0.0.0.0/0" {
					issues = append(issues, types.Issue{
						Rule:        r.GetName(),
						Message:     "Unrestricted ingress rule detected",
						Description: "Network security rules should not allow access from anywhere",
						Severity:    r.GetSeverity(),
						Line:        sourceAddressPrefix.Range.Start.Line,
					})
				}
			}
		}
	}

	return issues
}

// AzureDeprecatedResourcesRule detects usage of deprecated Azure resources
type AzureDeprecatedResourcesRule struct{}

func (r *AzureDeprecatedResourcesRule) GetName() string {
	return "AZURE_DEPRECATED_RESOURCES"
}
func (r *AzureDeprecatedResourcesRule) GetCategory() string { return "best-practices" }
func (r *AzureDeprecatedResourcesRule) GetProvider() string { return "azure" }
func (r *AzureDeprecatedResourcesRule) GetTags() []string { return []string{"best-practices", "azure", "deprecated"} }
func (r *AzureDeprecatedResourcesRule) GetVersion() string { return "1.0.0" }

func (r *AzureDeprecatedResourcesRule) GetDescription() string {
	return "Usage of deprecated Azure resources"
}

func (r *AzureDeprecatedResourcesRule) GetSeverity() string {
	return "medium"
}

func (r *AzureDeprecatedResourcesRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	deprecatedResources := []string{
		"azurerm_virtual_machine", // Use azurerm_linux_virtual_machine or azurerm_windows_virtual_machine
	}

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 {
			for _, deprecated := range deprecatedResources {
				if block.Labels[0] == deprecated {
					issues = append(issues, types.Issue{
						Rule:        r.GetName(),
						Message:     "Deprecated resource type used",
						Description: "Consider using newer Azure resource types for better security and features",
						Severity:    r.GetSeverity(),
						Line:        block.Range.Start.Line,
					})
					break
				}
			}
		}
	}

	return issues
}

// AzureMissingBackupRule detects resources without backup configurations
type AzureMissingBackupRule struct{}

func (r *AzureMissingBackupRule) GetName() string {
	return "AZURE_MISSING_BACKUP"
}
func (r *AzureMissingBackupRule) GetCategory() string { return "reliability" }
func (r *AzureMissingBackupRule) GetProvider() string { return "azure" }
func (r *AzureMissingBackupRule) GetTags() []string { return []string{"reliability", "azure", "backup"} }
func (r *AzureMissingBackupRule) GetVersion() string { return "1.0.0" }

func (r *AzureMissingBackupRule) GetDescription() string {
	return "Resources without backup configurations"
}

func (r *AzureMissingBackupRule) GetSeverity() string {
	return "high"
}

func (r *AzureMissingBackupRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "azurerm_sql_database" {
			if backupRetentionDays, exists := block.Attributes["backup_retention_days"]; exists {
				if ctyValueToString(backupRetentionDays.Value) == "0" {
					issues = append(issues, types.Issue{
						Rule:        r.GetName(),
						Message:     "SQL database backup retention not configured",
						Description: "Azure SQL databases should have backup retention configured",
						Severity:    r.GetSeverity(),
						Line:        backupRetentionDays.Range.Start.Line,
					})
				}
			}
		}
	}

	return issues
}

// AzureWeakCryptoRule detects weak cryptographic configurations
type AzureWeakCryptoRule struct{}

func (r *AzureWeakCryptoRule) GetName() string {
	return "AZURE_WEAK_CRYPTO"
}
func (r *AzureWeakCryptoRule) GetCategory() string { return "security" }
func (r *AzureWeakCryptoRule) GetProvider() string { return "azure" }
func (r *AzureWeakCryptoRule) GetTags() []string { return []string{"security", "azure", "cryptography"} }
func (r *AzureWeakCryptoRule) GetVersion() string { return "1.0.0" }

func (r *AzureWeakCryptoRule) GetDescription() string {
	return "Weak cryptographic configurations in Azure"
}

func (r *AzureWeakCryptoRule) GetSeverity() string {
	return "medium"
}

func (r *AzureWeakCryptoRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	for _, block := range config.Blocks {
		// Check for weak TLS versions in App Service
		if block.Type == "resource" && len(block.Labels) >= 2 && 
		   (block.Labels[0] == "azurerm_linux_web_app" || block.Labels[0] == "azurerm_windows_web_app") {
			
			// Check for missing HTTPS only setting
			if httpsOnly, exists := block.Attributes["https_only"]; exists {
				if ctyValueToString(httpsOnly.Value) == "false" {
					issues = append(issues, types.Issue{
						Rule:        r.GetName(),
						Message:     "HTTPS only not enforced",
						Description: "Web apps should enforce HTTPS only for security",
						Severity:    r.GetSeverity(),
						Line:        httpsOnly.Range.Start.Line,
					})
				}
			} else {
				// HTTPS only not specified (defaults to false)
				issues = append(issues, types.Issue{
					Rule:        r.GetName(),
					Message:     "HTTPS only setting not specified",
					Description: "Web apps should explicitly set https_only = true",
					Severity:    r.GetSeverity(),
					Line:        block.Range.Start.Line,
				})
			}

			// Check for weak TLS versions
			if minTlsVersion, exists := block.Attributes["min_tls_version"]; exists {
				if ctyValueToString(minTlsVersion.Value) == "1.0" || ctyValueToString(minTlsVersion.Value) == "1.1" {
					issues = append(issues, types.Issue{
						Rule:        r.GetName(),
						Message:     "Weak TLS version configured",
						Description: "Use TLS 1.2 or higher for better security",
						Severity:    r.GetSeverity(),
						Line:        minTlsVersion.Range.Start.Line,
					})
				}
			}
		}

		// Check for weak encryption in storage accounts
		if block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "azurerm_storage_account" {
			if encryption, exists := block.Attributes["encryption"]; exists {
				// Check if encryption is disabled
				if ctyValueToString(encryption.Value) == "false" {
					issues = append(issues, types.Issue{
						Rule:        r.GetName(),
						Message:     "Storage account encryption disabled",
						Description: "Azure storage accounts should have encryption enabled",
						Severity:    r.GetSeverity(),
						Line:        encryption.Range.Start.Line,
					})
				}
			}
		}
	}

	return issues
}

// AzureExcessivePermissionsRule detects excessive permissions in Azure
type AzureExcessivePermissionsRule struct{}

func (r *AzureExcessivePermissionsRule) GetName() string {
	return "AZURE_EXCESSIVE_PERMISSIONS"
}
func (r *AzureExcessivePermissionsRule) GetCategory() string { return "iam" }
func (r *AzureExcessivePermissionsRule) GetProvider() string { return "azure" }
func (r *AzureExcessivePermissionsRule) GetTags() []string { return []string{"security", "azure", "iam", "permissions"} }
func (r *AzureExcessivePermissionsRule) GetVersion() string { return "1.0.0" }

func (r *AzureExcessivePermissionsRule) GetDescription() string {
	return "Azure roles with excessive permissions"
}

func (r *AzureExcessivePermissionsRule) GetSeverity() string {
	return "high"
}

func (r *AzureExcessivePermissionsRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "azurerm_role_definition" {
			// Check for wildcard permissions
			if permissions, exists := block.Attributes["permissions"]; exists {
				// This is a simplified check - in practice, you'd parse the permissions JSON
				permStr := ctyValueToString(permissions.Value)
				if strings.Contains(permStr, `"*"`) || strings.Contains(permStr, `"Actions": "*"`) {
					issues = append(issues, types.Issue{
						Rule:        r.GetName(),
						Message:     "Excessive permissions detected",
						Description: "Azure role definitions should follow least privilege principle",
						Severity:    r.GetSeverity(),
						Line:        permissions.Range.Start.Line,
					})
				}
			}
		}
	}

	return issues
}

// AzureOpenPortsRule detects sensitive ports open to the world
type AzureOpenPortsRule struct{}

func (r *AzureOpenPortsRule) GetName() string {
	return "AZURE_OPEN_PORTS"
}
func (r *AzureOpenPortsRule) GetCategory() string { return "network" }
func (r *AzureOpenPortsRule) GetProvider() string { return "azure" }
func (r *AzureOpenPortsRule) GetTags() []string { return []string{"security", "azure", "network", "ports"} }
func (r *AzureOpenPortsRule) GetVersion() string { return "1.0.0" }

func (r *AzureOpenPortsRule) GetDescription() string {
	return "Sensitive ports open to the world in Azure"
}

func (r *AzureOpenPortsRule) GetSeverity() string {
	return "high"
}

func (r *AzureOpenPortsRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	sensitivePorts := []string{"22", "3389", "80", "443", "1433", "3306", "5432"}

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 && block.Labels[0] == "azurerm_network_security_rule" {
			if sourceAddressPrefix, exists := block.Attributes["source_address_prefix"]; exists {
				if ctyValueToString(sourceAddressPrefix.Value) == "*" || ctyValueToString(sourceAddressPrefix.Value) == "0.0.0.0/0" {
					if port, exists := block.Attributes["destination_port_range"]; exists {
						for _, sensitivePort := range sensitivePorts {
							if ctyValueToString(port.Value) == sensitivePort {
								issues = append(issues, types.Issue{
									Rule:        r.GetName(),
									Message:     "Sensitive port open to the world",
									Description: "Port " + sensitivePort + " should not be open to 0.0.0.0/0",
									Severity:    r.GetSeverity(),
									Line:        port.Range.Start.Line,
								})
								break
							}
						}
					}
				}
			}
		}
	}

	return issues
}

// AzureEncryptionComplianceRule detects missing encryption for compliance
type AzureEncryptionComplianceRule struct{}

func (r *AzureEncryptionComplianceRule) GetName() string {
	return "AZURE_ENCRYPTION_COMPLIANCE"
}
func (r *AzureEncryptionComplianceRule) GetCategory() string { return "compliance" }
func (r *AzureEncryptionComplianceRule) GetProvider() string { return "azure" }
func (r *AzureEncryptionComplianceRule) GetTags() []string { return []string{"security", "azure", "compliance", "encryption"} }
func (r *AzureEncryptionComplianceRule) GetVersion() string { return "1.0.0" }

func (r *AzureEncryptionComplianceRule) GetDescription() string {
	return "Missing encryption for compliance (HIPAA, SOC2, PCI-DSS)"
}

func (r *AzureEncryptionComplianceRule) GetSeverity() string {
	return "critical"
}

func (r *AzureEncryptionComplianceRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	// Check various Azure resources for encryption
	encryptionRequired := []string{
		"azurerm_storage_account",
		"azurerm_sql_server",
		"azurerm_managed_disk",
		"azurerm_key_vault",
	}

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 {
			for _, resourceType := range encryptionRequired {
				if block.Labels[0] == resourceType {
					if _, exists := block.Attributes["encryption"]; !exists {
						issues = append(issues, types.Issue{
							Rule:        r.GetName(),
							Message:     "Encryption attribute missing",
							Description: "Enable encryption for compliance (HIPAA, SOC2, PCI-DSS)",
							Severity:    r.GetSeverity(),
							Line:        block.Range.Start.Line,
						})
					}
					break
				}
			}
		}
	}

	return issues
}

// AzureCostOptimizationRule detects expensive Azure resources
type AzureCostOptimizationRule struct{}

func (r *AzureCostOptimizationRule) GetName() string {
	return "AZURE_COST_OPTIMIZATION"
}
func (r *AzureCostOptimizationRule) GetCategory() string { return "cost" }
func (r *AzureCostOptimizationRule) GetProvider() string { return "azure" }
func (r *AzureCostOptimizationRule) GetTags() []string { return []string{"cost", "azure", "optimization"} }
func (r *AzureCostOptimizationRule) GetVersion() string { return "1.0.0" }

func (r *AzureCostOptimizationRule) GetDescription() string {
	return "Large/expensive Azure instance types detected"
}

func (r *AzureCostOptimizationRule) GetSeverity() string {
	return "medium"
}

func (r *AzureCostOptimizationRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	expensiveVMSizes := []string{
		"Standard_E64s_v3", "Standard_E64s_v4", "Standard_E64s_v5",
		"Standard_M128s", "Standard_M128ms", "Standard_M64s", "Standard_M64ms",
		"Standard_NC24rs", "Standard_NC24rs_v3", "Standard_NC48rs_v3",
		"Standard_ND40rs_v2", "Standard_ND96asr_A100",
	}

	for _, block := range config.Blocks {
		if block.Type == "resource" && len(block.Labels) >= 2 {
			if block.Labels[0] == "azurerm_virtual_machine" || 
			   block.Labels[0] == "azurerm_linux_virtual_machine" || 
			   block.Labels[0] == "azurerm_windows_virtual_machine" {
				if vmSize, exists := block.Attributes["vm_size"]; exists {
					for _, expensive := range expensiveVMSizes {
						if ctyValueToString(vmSize.Value) == expensive {
							issues = append(issues, types.Issue{
								Rule:        r.GetName(),
								Message:     "Expensive VM size detected",
								Description: "Consider using smaller VM sizes for cost optimization",
								Severity:    r.GetSeverity(),
								Line:        vmSize.Range.Start.Line,
							})
							break
						}
					}
				}
			}
		}
	}

	return issues
}

// New rule: AzureWeakAuthenticationRule
type AzureWeakAuthenticationRule struct{}

func (r *AzureWeakAuthenticationRule) GetName() string {
	return "AZURE_WEAK_AUTHENTICATION"
}
func (r *AzureWeakAuthenticationRule) GetCategory() string { return "authentication" }
func (r *AzureWeakAuthenticationRule) GetProvider() string { return "azure" }
func (r *AzureWeakAuthenticationRule) GetTags() []string { return []string{"security", "azure", "authentication"} }
func (r *AzureWeakAuthenticationRule) GetVersion() string { return "1.0.0" }

func (r *AzureWeakAuthenticationRule) GetDescription() string {
	return "Weak authentication configurations in Azure"
}

func (r *AzureWeakAuthenticationRule) GetSeverity() string {
	return "high"
}

// Enhanced AzureWeakAuthenticationRule to properly parse complex data structures
func (r *AzureWeakAuthenticationRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	for _, block := range config.Blocks {
		// Check for weak authentication in app settings
		if block.Type == "resource" && len(block.Labels) >= 2 && 
		   (block.Labels[0] == "azurerm_linux_web_app" || block.Labels[0] == "azurerm_windows_web_app") {
			if appSettings, exists := block.Attributes["app_settings"]; exists {
				allValues := extractValuesFromCtyValue(appSettings.Value)
				
				// Check for debug mode enabled
				for _, value := range allValues {
					if strings.Contains(value, "APP_DEBUG") && strings.Contains(value, "true") {
						issues = append(issues, types.Issue{
							Rule:        r.GetName(),
							Message:     "Debug mode enabled in production",
							Description: "APP_DEBUG should be false in production environments",
							Severity:    r.GetSeverity(),
							Line:        appSettings.Range.Start.Line,
						})
						break
					}
				}

				// Check for weak session configuration
				for _, value := range allValues {
					if strings.Contains(value, "APP_KEY") && 
					   !strings.Contains(value, "var.") && 
					   !strings.Contains(value, "data.") &&
					   len(value) > 10 {
						issues = append(issues, types.Issue{
							Rule:        r.GetName(),
							Message:     "Weak application key configuration",
							Description: "APP_KEY should be stored securely and not hardcoded",
							Severity:    r.GetSeverity(),
							Line:        appSettings.Range.Start.Line,
						})
						break
					}
				}
			}
		}

		// Check variable blocks for weak authentication settings
		if block.Type == "variable" && len(block.Labels) >= 1 {
			if defaultValue, exists := block.Attributes["default"]; exists {
				allValues := extractValuesFromCtyValue(defaultValue.Value)
				
				// Check for debug mode enabled
				for _, value := range allValues {
					if strings.Contains(value, "APP_DEBUG") && strings.Contains(value, "true") {
						issues = append(issues, types.Issue{
							Rule:        r.GetName(),
							Message:     "Debug mode enabled in variable default",
							Description: "APP_DEBUG should be false in production environments",
							Severity:    r.GetSeverity(),
							Line:        defaultValue.Range.Start.Line,
						})
						break
					}
				}

				// Check for weak session configuration in variables
				for _, value := range allValues {
					if strings.Contains(value, "APP_KEY") && 
					   !strings.Contains(value, "var.") && 
					   !strings.Contains(value, "data.") &&
					   len(value) > 10 {
						issues = append(issues, types.Issue{
							Rule:        r.GetName(),
							Message:     "Weak application key configuration in variable default",
							Description: "APP_KEY should be stored securely and not hardcoded in variable defaults",
							Severity:    r.GetSeverity(),
							Line:        defaultValue.Range.Start.Line,
						})
						break
					}
				}
			}
		}

		// Enhanced detection for specific weak authentication patterns
		for _, attr := range block.Attributes {
			value := ctyValueToString(attr.Value)
			
			// Check for debug mode in any attribute
			if strings.Contains(value, "APP_DEBUG") && strings.Contains(value, "true") {
				issues = append(issues, types.Issue{
					Rule:        r.GetName(),
					Message:     "Debug mode enabled",
					Description: "APP_DEBUG should be false in production environments",
					Severity:    r.GetSeverity(),
					Line:        attr.Range.Start.Line,
				})
			}
			
			// Check for weak session timeouts
			if strings.Contains(value, "SESSION_LIFETIME") && 
			   (strings.Contains(value, "0") || strings.Contains(value, "null")) {
				issues = append(issues, types.Issue{
					Rule:        r.GetName(),
					Message:     "Weak session lifetime configuration",
					Description: "Session lifetime should be set to a reasonable value for security",
					Severity:    r.GetSeverity(),
					Line:        attr.Range.Start.Line,
				})
			}
		}
	}

	return issues
}

// Enhanced AzureExposedSecretsRule to properly parse complex data structures
func (r *AzureExposedSecretsRule) Check(config *parser.Config) []types.Issue {
	var issues []types.Issue

	for _, block := range config.Blocks {
		// Use the RawValue field which contains the actual string representation
		for _, attr := range block.Attributes {
			rawValue := attr.RawValue
			
			// Check for hardcoded secrets in the raw value
			if strings.Contains(rawValue, "APP_KEY") && strings.Contains(rawValue, "base64:") {
				issues = append(issues, types.Issue{
					Rule:        r.GetName(),
					Message:     "Hardcoded APP_KEY detected",
					Description: "APP_KEY should not be hardcoded. Use Azure Key Vault or environment variables.",
					Severity:    r.GetSeverity(),
					Line:        attr.Range.Start.Line,
				})
			}
			
			if strings.Contains(rawValue, "DATABASE_URL") && strings.Contains(rawValue, "postgres://") && strings.Contains(rawValue, "@") {
				issues = append(issues, types.Issue{
					Rule:        r.GetName(),
					Message:     "Hardcoded database connection string with credentials",
					Description: "Database connection strings should not contain hardcoded credentials.",
					Severity:    r.GetSeverity(),
					Line:        attr.Range.Start.Line,
				})
			}
			
			if strings.Contains(rawValue, "MICROSOFT_CLIENT_SECRET") {
				issues = append(issues, types.Issue{
					Rule:        r.GetName(),
					Message:     "Hardcoded Microsoft client secret",
					Description: "Microsoft OAuth client secrets should not be hardcoded.",
					Severity:    r.GetSeverity(),
					Line:        attr.Range.Start.Line,
				})
			}
			
			if strings.Contains(rawValue, "APP_DEBUG") && strings.Contains(rawValue, "true") {
				issues = append(issues, types.Issue{
					Rule:        "AZURE_WEAK_AUTHENTICATION",
					Message:     "Debug mode enabled in production",
					Description: "APP_DEBUG should be false in production environments.",
					Severity:    "high",
					Line:        attr.Range.Start.Line,
				})
			}
		}
		
		// Check provider blocks for hardcoded credentials
		if block.Type == "provider" && len(block.Labels) >= 1 && block.Labels[0] == "azurerm" {
			for attrName, attr := range block.Attributes {
				if attrName == "client_secret" || attrName == "client_id" || attrName == "tenant_id" || attrName == "subscription_id" {
					rawValue := attr.RawValue
					
					// Check if it looks like a hardcoded value (not a variable reference)
					if len(rawValue) > 10 && !strings.Contains(rawValue, "var.") && !strings.Contains(rawValue, "data.") {
						issues = append(issues, types.Issue{
							Rule:        r.GetName(),
							Message:     "Hardcoded Azure provider credential: " + attrName,
							Description: "Azure provider credentials should be stored in variables or environment.",
							Severity:    r.GetSeverity(),
							Line:        attr.Range.Start.Line,
						})
					}
				}
			}
		}
	}

	return issues
} 