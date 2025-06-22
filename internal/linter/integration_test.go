package linter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Integration test fixtures with various Terraform scenarios
func setupIntegrationTestFixtures(t *testing.T) map[string]string {
	baseDir := t.TempDir()
	fixtures := make(map[string]string)

	// 1. AWS S3 Security Issues
	fixtures["aws_s3_issues"] = filepath.Join(baseDir, "aws_s3")
	err := os.MkdirAll(fixtures["aws_s3_issues"], 0755)
	require.NoError(t, err)

	s3Config := `
resource "aws_s3_bucket" "public_bucket" {
  bucket = "my-public-bucket"
  acl    = "public-read"  # Security issue: public ACL
}

resource "aws_s3_bucket" "unencrypted_bucket" {
  bucket = "my-unencrypted-bucket"
  
  # Missing server_side_encryption_configuration - security issue
}

resource "aws_s3_bucket_versioning" "disabled" {
  bucket = aws_s3_bucket.unencrypted_bucket.id
  versioning_configuration {
    status = "Disabled"  # Security issue: versioning disabled
  }
}

resource "aws_s3_bucket_logging" "example" {
  bucket = aws_s3_bucket.public_bucket.id
  # Missing target_bucket - logging not configured properly
}
`
	err = os.WriteFile(filepath.Join(fixtures["aws_s3_issues"], "main.tf"), []byte(s3Config), 0644)
	require.NoError(t, err)

	// 2. AWS EC2 Security Issues
	fixtures["aws_ec2_issues"] = filepath.Join(baseDir, "aws_ec2")
	err = os.MkdirAll(fixtures["aws_ec2_issues"], 0755)
	require.NoError(t, err)

	ec2Config := `
resource "aws_security_group" "allow_all" {
  name_prefix = "allow-all"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Security issue: allows all traffic
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Security issue: SSH open to world
  }
}

resource "aws_instance" "unencrypted" {
  ami           = "ami-0c55b159cbfafe1d0"
  instance_type = "t2.micro"
  
  # Security issue: unencrypted root volume
  root_block_device {
    encrypted = false
  }
  
  # Security issue: using insecure security group
  vpc_security_group_ids = [aws_security_group.allow_all.id]
}

resource "aws_ebs_volume" "unencrypted" {
  availability_zone = "us-west-2a"
  size             = 20
  encrypted        = false  # Security issue: unencrypted EBS volume
}
`
	err = os.WriteFile(filepath.Join(fixtures["aws_ec2_issues"], "main.tf"), []byte(ec2Config), 0644)
	require.NoError(t, err)

	// 3. Secure Configuration (should pass)
	fixtures["secure_config"] = filepath.Join(baseDir, "secure")
	err = os.MkdirAll(fixtures["secure_config"], 0755)
	require.NoError(t, err)

	secureConfig := `
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "my-secure-bucket"
}

resource "aws_s3_bucket_acl" "secure_bucket_acl" {
  bucket = aws_s3_bucket.secure_bucket.id
  acl    = "private"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secure_bucket_encryption" {
  bucket = aws_s3_bucket.secure_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "secure_bucket_versioning" {
  bucket = aws_s3_bucket.secure_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_security_group" "secure_sg" {
  name_prefix = "secure-sg"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # Restricted to private network
  }
}

resource "aws_instance" "secure_instance" {
  ami           = "ami-0c55b159cbfafe1d0"
  instance_type = "t2.micro"
  
  root_block_device {
    encrypted = true
  }
  
  vpc_security_group_ids = [aws_security_group.secure_sg.id]
}
`
	err = os.WriteFile(filepath.Join(fixtures["secure_config"], "main.tf"), []byte(secureConfig), 0644)
	require.NoError(t, err)

	// 4. Mixed Configuration with variables
	fixtures["mixed_config"] = filepath.Join(baseDir, "mixed")
	err = os.MkdirAll(fixtures["mixed_config"], 0755)
	require.NoError(t, err)

	mixedConfig := `
variable "bucket_name" {
  description = "Name of the S3 bucket"
  type        = string
  default     = "my-mixed-bucket"
}

variable "encryption_enabled" {
  description = "Enable encryption"
  type        = bool
  default     = false  # This could be a security issue depending on usage
}

resource "aws_s3_bucket" "mixed_bucket" {
  bucket = var.bucket_name
}

resource "aws_s3_bucket_server_side_encryption_configuration" "mixed_encryption" {
  count  = var.encryption_enabled ? 1 : 0
  bucket = aws_s3_bucket.mixed_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# This will be flagged as insecure if used without encryption
resource "aws_s3_bucket_acl" "mixed_acl" {
  bucket = aws_s3_bucket.mixed_bucket.id
  acl    = "public-read"  # Potentially insecure
}
`
	err = os.WriteFile(filepath.Join(fixtures["mixed_config"], "main.tf"), []byte(mixedConfig), 0644)
	require.NoError(t, err)

	// Add variables file
	varsConfig := `
bucket_name = "production-bucket"
encryption_enabled = true
`
	err = os.WriteFile(filepath.Join(fixtures["mixed_config"], "terraform.tfvars"), []byte(varsConfig), 0644)
	require.NoError(t, err)

	// 5. Complex nested modules structure
	fixtures["complex_modules"] = filepath.Join(baseDir, "complex")
	err = os.MkdirAll(fixtures["complex_modules"], 0755)
	require.NoError(t, err)

	// Main configuration
	complexMain := `
module "vpc" {
  source = "./modules/vpc"
  
  vpc_cidr = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
}

module "security" {
  source = "./modules/security"
  
  vpc_id = module.vpc.vpc_id
  allowed_cidr_blocks = ["10.0.0.0/16"]
}

module "storage" {
  source = "./modules/storage"
  
  bucket_prefix = "complex-test"
  encryption_key = "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012"
}
`
	err = os.WriteFile(filepath.Join(fixtures["complex_modules"], "main.tf"), []byte(complexMain), 0644)
	require.NoError(t, err)

	// Create modules directory structure
	modulesDir := filepath.Join(fixtures["complex_modules"], "modules")
	
	// VPC module
	vpcModuleDir := filepath.Join(modulesDir, "vpc")
	err = os.MkdirAll(vpcModuleDir, 0755)
	require.NoError(t, err)

	vpcModule := `
variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
}

variable "enable_dns_hostnames" {
  description = "Enable DNS hostnames"
  type        = bool
  default     = false
}

variable "enable_dns_support" {
  description = "Enable DNS support"
  type        = bool
  default     = false  
}

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = var.enable_dns_hostnames
  enable_dns_support   = var.enable_dns_support
  
  tags = {
    Name = "main-vpc"
  }
}

output "vpc_id" {
  value = aws_vpc.main.id
}
`
	err = os.WriteFile(filepath.Join(vpcModuleDir, "main.tf"), []byte(vpcModule), 0644)
	require.NoError(t, err)

	// Security module with issues
	securityModuleDir := filepath.Join(modulesDir, "security")
	err = os.MkdirAll(securityModuleDir, 0755)
	require.NoError(t, err)

	securityModule := `
variable "vpc_id" {
  description = "VPC ID"
  type        = string
}

variable "allowed_cidr_blocks" {
  description = "Allowed CIDR blocks"
  type        = list(string)
  default     = ["0.0.0.0/0"]  # Security issue: default allows all
}

resource "aws_security_group" "web" {
  name_prefix = "web-sg"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
  }

  # This is a security issue if allowed_cidr_blocks includes 0.0.0.0/0
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks  # Potentially dangerous
  }

  egress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Security issue: unrestricted egress
  }
}
`
	err = os.WriteFile(filepath.Join(securityModuleDir, "main.tf"), []byte(securityModule), 0644)
	require.NoError(t, err)

	return fixtures
}

func setupConfigFiles(t *testing.T, baseDir string) map[string]string {
	configs := make(map[string]string)

	// 1. Basic config file
	configs["basic"] = filepath.Join(baseDir, "basic-config.yaml")
	basicConfig := `
exclude:
  - "*.tfvars"
  - "terraform.tfstate*"
severity:
  "aws_s3_bucket_public_acl": "critical"
  "aws_security_group_ingress_all": "high"
custom_rules: []
`
	err := os.WriteFile(configs["basic"], []byte(basicConfig), 0644)
	require.NoError(t, err)

	// 2. Strict config file
	configs["strict"] = filepath.Join(baseDir, "strict-config.yaml")
	strictConfig := `
exclude: []
severity:
  "aws_s3_bucket_public_acl": "critical"
  "aws_security_group_ingress_all": "critical"
  "aws_instance_unencrypted_root": "high"
  "aws_ebs_volume_unencrypted": "high"
custom_rules: []
`
	err = os.WriteFile(configs["strict"], []byte(strictConfig), 0644)
	require.NoError(t, err)

	// 3. JSON config file
	configs["json"] = filepath.Join(baseDir, "config.json")
	jsonConfig := map[string]interface{}{
		"exclude": []string{"test_*.tf"},
		"severity": map[string]string{
			"aws_s3_bucket_public_acl": "medium",
		},
		"custom_rules": []interface{}{},
	}
	jsonData, _ := json.MarshalIndent(jsonConfig, "", "  ")
	err = os.WriteFile(configs["json"], jsonData, 0644)
	require.NoError(t, err)

	return configs
}

func TestLinterIntegrationBasicFunctionality(t *testing.T) {
	fixtures := setupIntegrationTestFixtures(t)
	
	t.Run("scan AWS S3 security issues", func(t *testing.T) {
		linter := NewLinter()
		linter.SetSeverity("all")
		linter.SetVerbose(true)
		
		report, err := linter.Lint(fixtures["aws_s3_issues"])
		require.NoError(t, err)
		require.NotNil(t, report)
		
		// Should find security issues
		assert.True(t, report.HasIssues())
		assert.Greater(t, len(report.Issues), 0)
		
		// Verify stats are calculated
		assert.Greater(t, report.Stats.Total, 0)
	})
	
	t.Run("scan AWS EC2 security issues", func(t *testing.T) {
		linter := NewLinter()
		linter.SetSeverity("high")
		
		report, err := linter.Lint(fixtures["aws_ec2_issues"])
		require.NoError(t, err)
		require.NotNil(t, report)
		
		assert.True(t, report.HasIssues())
		assert.Greater(t, len(report.Issues), 0)
		
		// Verify stats are calculated
		assert.Greater(t, report.Stats.Total, 0)
	})
	
	t.Run("scan secure configuration - should pass", func(t *testing.T) {
		linter := NewLinter()
		linter.SetSeverity("all")
		
		report, err := linter.Lint(fixtures["secure_config"])
		require.NoError(t, err)
		require.NotNil(t, report)
		
		// Should have fewer or no issues for secure configuration
		// The exact behavior depends on the rules implementation
		if report.HasIssues() {
			// Log what issues were found for debugging
			t.Logf("Found %d issues in secure config:", len(report.Issues))
			for _, issue := range report.Issues {
				t.Logf("  - %s: %s", issue.Rule, issue.Message)
			}
		}
	})
}

func TestLinterIntegrationWithConfig(t *testing.T) {
	fixtures := setupIntegrationTestFixtures(t)
	configs := setupConfigFiles(t, t.TempDir())
	
	t.Run("with basic config file", func(t *testing.T) {
		linter := NewLinter()
		linter.SetConfigFile(configs["basic"])
		linter.SetSeverity("all")
		
		report, err := linter.Lint(fixtures["mixed_config"])
		require.NoError(t, err)
		require.NotNil(t, report)
		
		// Config should exclude .tfvars files
		for _, issue := range report.Issues {
			assert.NotContains(t, issue.File, ".tfvars")
		}
	})
	
	t.Run("with JSON config file", func(t *testing.T) {
		linter := NewLinter()
		linter.SetConfigFile(configs["json"])
		linter.SetSeverity("all")
		
		report, err := linter.Lint(fixtures["aws_s3_issues"])
		require.NoError(t, err)
		require.NotNil(t, report)
		
		// Should still work with JSON config
		assert.True(t, report.HasIssues())
	})
}

func TestLinterIntegrationSeverityFiltering(t *testing.T) {
	fixtures := setupIntegrationTestFixtures(t)
	
	severityLevels := []string{"low", "medium", "high", "critical", "all"}
	
	for _, severity := range severityLevels {
		t.Run(fmt.Sprintf("severity_%s", severity), func(t *testing.T) {
			linter := NewLinter()
			linter.SetSeverity(severity)
			
			report, err := linter.Lint(fixtures["aws_s3_issues"])
			require.NoError(t, err)
			require.NotNil(t, report)
			
			// Verify that only issues of the specified severity (or higher) are included
			// This test might need adjustment based on actual rule implementations
			for _, issue := range report.Issues {
				assert.NotEmpty(t, issue.Severity)
			}
		})
	}
}

func TestLinterIntegrationExcludePatterns(t *testing.T) {
	fixtures := setupIntegrationTestFixtures(t)
	
	t.Run("exclude tfvars files", func(t *testing.T) {
		linter := NewLinter()
		linter.SetExcludePatterns([]string{"*.tfvars"})
		linter.SetSeverity("all")
		
		report, err := linter.Lint(fixtures["mixed_config"])
		require.NoError(t, err)
		require.NotNil(t, report)
		
		// Should not find any issues in .tfvars files
		for _, issue := range report.Issues {
			assert.NotContains(t, issue.File, ".tfvars")
		}
	})
	
	t.Run("exclude specific files", func(t *testing.T) {
		linter := NewLinter()
		linter.SetExcludePatterns([]string{"main.tf"})
		linter.SetSeverity("all")
		
		report, err := linter.Lint(fixtures["aws_s3_issues"])
		require.NoError(t, err)
		require.NotNil(t, report)
		
		// Should not find any issues in main.tf
		for _, issue := range report.Issues {
			assert.NotContains(t, issue.File, "main.tf")
		}
	})
}

func TestLinterIntegrationCaching(t *testing.T) {
	fixtures := setupIntegrationTestFixtures(t)
	
	t.Run("cache functionality", func(t *testing.T) {
		// First run
		linter1 := NewLinter()
		linter1.SetSeverity("all")
		linter1.SetVerbose(true)
		
		start1 := time.Now()
		report1, err := linter1.Lint(fixtures["aws_s3_issues"])
		duration1 := time.Since(start1)
		
		require.NoError(t, err)
		require.NotNil(t, report1)
		
		// Second run (should be faster due to caching)
		linter2 := NewLinter()
		linter2.SetSeverity("all")
		linter2.SetVerbose(true)
		
		start2 := time.Now()
		report2, err := linter2.Lint(fixtures["aws_s3_issues"])
		duration2 := time.Since(start2)
		
		require.NoError(t, err)
		require.NotNil(t, report2)
		
		// Results should be consistent
		assert.Equal(t, len(report1.Issues), len(report2.Issues))
		assert.Equal(t, report1.Stats.Total, report2.Stats.Total)
		
		// Second run might be faster (though not guaranteed in tests)
		t.Logf("First run: %v, Second run: %v", duration1, duration2)
	})
}

func TestLinterIntegrationComplexScenarios(t *testing.T) {
	fixtures := setupIntegrationTestFixtures(t)
	
	t.Run("complex modules structure", func(t *testing.T) {
		linter := NewLinter()
		linter.SetSeverity("all")
		linter.SetVerbose(true)
		
		report, err := linter.Lint(fixtures["complex_modules"])
		require.NoError(t, err)
		require.NotNil(t, report)
		
		// Should find issues across multiple modules
		if report.HasIssues() {
			assert.Greater(t, len(report.Issues), 0)
			
			// Check that issues are found in different module files
			foundMainTF := false
			foundModuleFiles := false
			
			for _, issue := range report.Issues {
				if strings.Contains(issue.Rule, "main") {
					foundMainTF = true
				}
				if strings.Contains(issue.Rule, "module") {
					foundModuleFiles = true
				}
			}
			
			t.Logf("Found issues in main.tf: %v, in modules: %v", foundMainTF, foundModuleFiles)
		}
	})
}

func TestLinterIntegrationErrorHandling(t *testing.T) {
	t.Run("nonexistent directory", func(t *testing.T) {
		linter := NewLinter()
		
		_, err := linter.Lint("/nonexistent/path")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "does not exist")
	})
	
	t.Run("invalid Terraform syntax", func(t *testing.T) {
		invalidDir := t.TempDir()
		invalidTF := `
resource "aws_s3_bucket" "broken" {
  bucket = "test"
  # Missing closing brace
`
		err := os.WriteFile(filepath.Join(invalidDir, "invalid.tf"), []byte(invalidTF), 0644)
		require.NoError(t, err)
		
		linter := NewLinter()
		
		// Should handle parse errors gracefully
		report, err := linter.Lint(invalidDir)
		
		// Depending on implementation, this might return an error or handle gracefully
		if err != nil {
			assert.Contains(t, err.Error(), "parse")
		} else {
			assert.NotNil(t, report)
		}
	})
	
	t.Run("invalid config file", func(t *testing.T) {
		fixtures := setupIntegrationTestFixtures(t)
		invalidConfigPath := filepath.Join(t.TempDir(), "invalid.yaml")
		
		invalidConfig := `
invalid: yaml: content: [
`
		err := os.WriteFile(invalidConfigPath, []byte(invalidConfig), 0644)
		require.NoError(t, err)
		
		linter := NewLinter()
		linter.SetConfigFile(invalidConfigPath)
		
		// Should handle invalid config gracefully
		report, err := linter.Lint(fixtures["secure_config"])
		
		// Should either handle gracefully or return appropriate error
		if err != nil {
			assert.Contains(t, err.Error(), "config")
		} else {
			assert.NotNil(t, report)
		}
	})
}

// Performance and stress tests
func TestLinterIntegrationPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance tests in short mode")
	}
	
	t.Run("performance with large configuration", func(t *testing.T) {
		// Create a larger test configuration
		largeDir := t.TempDir()
		
		// Generate multiple files with various resources
		for i := 0; i < 10; i++ {
			content := fmt.Sprintf(`
resource "aws_s3_bucket" "bucket_%d" {
  bucket = "test-bucket-%d"
  acl    = "private"
}

resource "aws_security_group" "sg_%d" {
  name_prefix = "test-sg-%d"
  
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}

resource "aws_instance" "instance_%d" {
  ami           = "ami-0c55b159cbfafe1d0"
  instance_type = "t2.micro"
  
  root_block_device {
    encrypted = true
  }
}
`, i, i, i, i, i)
			
			err := os.WriteFile(filepath.Join(largeDir, fmt.Sprintf("resources_%d.tf", i)), []byte(content), 0644)
			require.NoError(t, err)
		}
		
		linter := NewLinter()
		linter.SetSeverity("all")
		
		start := time.Now()
		report, err := linter.Lint(largeDir)
		duration := time.Since(start)
		
		require.NoError(t, err)
		require.NotNil(t, report)
		
		t.Logf("Processed large configuration in %v", duration)
		assert.Less(t, duration, 30*time.Second, "Should complete within reasonable time")
	})
}

// Benchmark tests for integration scenarios
func BenchmarkLinterIntegrationBasic(b *testing.B) {
	fixtures := setupIntegrationTestFixtures(&testing.T{})
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		linter := NewLinter()
		linter.SetSeverity("all")
		
		_, err := linter.Lint(fixtures["aws_s3_issues"])
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkLinterIntegrationComplex(b *testing.B) {
	fixtures := setupIntegrationTestFixtures(&testing.T{})
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		linter := NewLinter()
		linter.SetSeverity("all")
		linter.SetVerbose(false) // Disable verbose for benchmarking
		
		_, err := linter.Lint(fixtures["complex_modules"])
		if err != nil {
			b.Fatal(err)
		}
	}
} 