package tests

import (
	"testing"

	"github.com/heyimusa/go-terraform-linter/internal/rules/security"
)

func TestAzureExposedSecretsRule(t *testing.T) {
	rule := &security.AzureExposedSecretsRule{}
	
	tests := []struct {
		name     string
		config   string
		expected int
		description string
	}{
		{
			name: "should detect hardcoded client_secret",
			config: `
terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~>3.0"
    }
  }
}

provider "azurerm" {
  features {}
  client_id     = "test-client-id"
  client_secret = "hardcoded-secret-123"
}
`,
			expected: 1,
			description: "Hardcoded Azure provider credentials detected",
		},
		{
			name: "should detect hardcoded APP_KEY",
			config: `
resource "azurerm_app_service" "test" {
  name                = "test-app"
  location            = "West Europe"
  resource_group_name = "test-rg"
  
  app_settings = {
    "APP_KEY" = "base64:hardcoded-app-key-123"
  }
}
`,
			expected: 1,
			description: "Hardcoded APP_KEY detected",
		},
		{
			name: "should detect database connection string with credentials",
			config: `
resource "azurerm_app_service" "test" {
  name                = "test-app"
  location            = "West Europe"
  resource_group_name = "test-rg"
  
  app_settings = {
    "DATABASE_URL" = "mysql://user:password123@localhost:3306/db"
  }
}
`,
			expected: 1,
			description: "Database connection string with credentials detected",
		},
		{
			name: "should not detect secrets in variables",
			config: `
variable "client_secret" {
  description = "Azure client secret"
  type        = string
  sensitive   = true
}

provider "azurerm" {
  features {}
  client_id     = var.client_id
  client_secret = var.client_secret
}
`,
			expected: 0,
			description: "No secrets detected when using variables",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := parseTestConfig(t, tt.config)
			issues := rule.Check(config)
			
			if len(issues) != tt.expected {
				t.Errorf("Expected %d issues, got %d", tt.expected, len(issues))
				for _, issue := range issues {
					t.Logf("Issue: %s - %s", issue.Rule, issue.Message)
				}
			}
			
			if len(issues) > 0 {
				issue := issues[0]
				if issue.Rule != rule.GetName() {
					t.Errorf("Expected rule %s, got %s", rule.GetName(), issue.Rule)
				}
				if issue.Severity != rule.GetSeverity() {
					t.Errorf("Expected severity %s, got %s", rule.GetSeverity(), issue.Severity)
				}
			}
		})
	}
}

func TestAzurePublicAccessRule(t *testing.T) {
	rule := &security.AzurePublicAccessRule{}
	
	tests := []struct {
		name     string
		config   string
		expected int
	}{
		{
			name: "should detect public storage account",
			config: `
resource "azurerm_storage_account" "test" {
  name                     = "teststorage"
  resource_group_name      = "test-rg"
  location                 = "West Europe"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  public_network_access_enabled = true
}
`,
			expected: 1,
		},
		{
			name: "should detect public container registry",
			config: `
resource "azurerm_container_registry" "test" {
  name                = "testregistry"
  resource_group_name = "test-rg"
  location            = "West Europe"
  sku                 = "Basic"
  public_network_access_enabled = true
}
`,
			expected: 1,
		},
		{
			name: "should not detect private resources",
			config: `
resource "azurerm_storage_account" "test" {
  name                     = "teststorage"
  resource_group_name      = "test-rg"
  location                 = "West Europe"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  public_network_access_enabled = false
}
`,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := parseTestConfig(t, tt.config)
			issues := rule.Check(config)
			
			if len(issues) != tt.expected {
				t.Errorf("Expected %d issues, got %d", tt.expected, len(issues))
			}
		})
	}
}

func TestAzureUnencryptedStorageRule(t *testing.T) {
	rule := &security.AzureUnencryptedStorageRule{}
	
	tests := []struct {
		name     string
		config   string
		expected int
	}{
		{
			name: "should detect unencrypted storage account",
			config: `
resource "azurerm_storage_account" "test" {
  name                     = "teststorage"
  resource_group_name      = "test-rg"
  location                 = "West Europe"
  account_tier             = "Standard"
  account_replication_type = "LRS"
}
`,
			expected: 1,
		},
		{
			name: "should detect unencrypted managed disk",
			config: `
resource "azurerm_managed_disk" "test" {
  name                 = "test-disk"
  location             = "West Europe"
  resource_group_name  = "test-rg"
  storage_account_type = "Standard_LRS"
  create_option        = "Empty"
  disk_size_gb         = 10
}
`,
			expected: 1,
		},
		{
			name: "should not detect encrypted storage",
			config: `
resource "azurerm_storage_account" "test" {
  name                     = "teststorage"
  resource_group_name      = "test-rg"
  location                 = "West Europe"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  
  encryption {
    services {
      blob {
        enabled = true
      }
      file {
        enabled = true
      }
    }
  }
}
`,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := parseTestConfig(t, tt.config)
			issues := rule.Check(config)
			
			if len(issues) != tt.expected {
				t.Errorf("Expected %d issues, got %d", tt.expected, len(issues))
			}
		})
	}
} 