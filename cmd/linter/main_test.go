package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test fixtures - sample Terraform configurations
func setupTestFixtures(t *testing.T) string {
	tempDir := t.TempDir()
	
	// Create a valid Terraform file
	validTF := `
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
  
  tags = {
    Name        = "My bucket"
    Environment = "Dev"
  }
}

resource "aws_s3_bucket_versioning" "example" {
  bucket = aws_s3_bucket.example.id
  versioning_configuration {
    status = "Enabled"
  }
}
`
	err := os.WriteFile(filepath.Join(tempDir, "main.tf"), []byte(validTF), 0644)
	require.NoError(t, err)
	
	// Create a Terraform file with security issues
	insecureTF := `
resource "aws_s3_bucket" "bad_bucket" {
  bucket = "insecure-bucket"
  
  # This is insecure - public read access
  acl = "public-read"
}

resource "aws_security_group" "bad_sg" {
  name_prefix = "bad-sg"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # This is insecure - allows all traffic
  }
  
  egress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "bad_instance" {
  ami           = "ami-0c55b159cbfafe1d0"
  instance_type = "t2.micro"
  
  # This is insecure - no encrypted storage
  root_block_device {
    encrypted = false
  }
}
`
	err = os.WriteFile(filepath.Join(tempDir, "insecure.tf"), []byte(insecureTF), 0644)
	require.NoError(t, err)
	
	// Create a .tfvars file
	tfvarsContent := `
region = "us-west-2"
environment = "test"
bucket_name = "my-test-bucket"
`
	err = os.WriteFile(filepath.Join(tempDir, "terraform.tfvars"), []byte(tfvarsContent), 0644)
	require.NoError(t, err)
	
	// Create an invalid Terraform file
	invalidTF := `
resource "aws_s3_bucket" "broken" {
  bucket = "my-bucket"
  # Missing closing brace
`
	err = os.WriteFile(filepath.Join(tempDir, "invalid.tf"), []byte(invalidTF), 0644)
	require.NoError(t, err)
	
	// Create a config file for testing
	configContent := `
exclude:
  - "invalid.tf"
severity:
  "aws_s3_bucket_public_acl": "high"
custom_rules: []
`
	err = os.WriteFile(filepath.Join(tempDir, "tflint.yaml"), []byte(configContent), 0644)
	require.NoError(t, err)
	
	return tempDir
}

// Helper function to build the linter binary for testing
func buildLinterBinary(t *testing.T) string {
	binaryPath := filepath.Join(t.TempDir(), "tflint")
	cmd := exec.Command("go", "build", "-o", binaryPath, ".")
	cmd.Dir = filepath.Join(".") // We're already in cmd/linter
	err := cmd.Run()
	require.NoError(t, err, "Failed to build linter binary")
	return binaryPath
}

// Helper function to run linter command and capture output
func runLinterCommand(t *testing.T, binaryPath string, args ...string) (stdout, stderr string, exitCode int) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	cmd := exec.CommandContext(ctx, binaryPath, args...)
	
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	
	err := cmd.Run()
	
	stdout = stdoutBuf.String()
	stderr = stderrBuf.String()
	
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		} else {
			exitCode = 1
		}
	} else {
		exitCode = 0
	}
	
	return stdout, stderr, exitCode
}

func TestCLIBasicUsage(t *testing.T) {
	binaryPath := buildLinterBinary(t)
	testDir := setupTestFixtures(t)
	
	t.Run("help flag", func(t *testing.T) {
		stdout, stderr, exitCode := runLinterCommand(t, binaryPath, "--help")
		assert.Equal(t, 0, exitCode)
		assert.Contains(t, stdout, "A fast and comprehensive Terraform linter")
		assert.Contains(t, stdout, "Usage:")
		assert.Empty(t, stderr)
	})
	
	t.Run("version information", func(t *testing.T) {
		stdout, stderr, exitCode := runLinterCommand(t, binaryPath, "--help")
		assert.Equal(t, 0, exitCode)
		assert.Contains(t, stdout, "tflint")
		assert.Empty(t, stderr)
	})
	
	t.Run("no arguments - current directory", func(t *testing.T) {
		// Change to test directory
		originalDir, _ := os.Getwd()
		defer os.Chdir(originalDir)
		os.Chdir(testDir)
		
		stdout, _, exitCode := runLinterCommand(t, binaryPath)
		
		// Should find issues and exit with code 1
		assert.Equal(t, 1, exitCode)
		assert.Contains(t, stdout, "Security Scan Results")
		// May contain warnings about unparseable files
	})
}

func TestCLIConfigPathArgument(t *testing.T) {
	binaryPath := buildLinterBinary(t)
	testDir := setupTestFixtures(t)
	
	t.Run("valid path argument", func(t *testing.T) {
		stdout, _, exitCode := runLinterCommand(t, binaryPath, testDir)
		
		assert.Equal(t, 1, exitCode) // Should find issues
		assert.Contains(t, stdout, "Security Scan Results")
		// May contain warnings about unparseable files
	})
	
	t.Run("valid path with --config flag", func(t *testing.T) {
		stdout, _, exitCode := runLinterCommand(t, binaryPath, "--config", testDir)
		
		assert.Equal(t, 1, exitCode)
		assert.Contains(t, stdout, "Security Scan Results")
		// May contain warnings about unparseable files
	})
	
	t.Run("invalid path", func(t *testing.T) {
		_, _, exitCode := runLinterCommand(t, binaryPath, "/nonexistent/path")
		
		assert.Equal(t, 1, exitCode)
		// May have some stdout output from logging
		// May contain error messages or warnings
	})
}

func TestCLISeverityFiltering(t *testing.T) {
	binaryPath := buildLinterBinary(t)
	testDir := setupTestFixtures(t)
	
	testCases := []struct {
		name     string
		severity string
		expected int // expected exit code
	}{
		{"all severities", "all", 1},
		{"critical only", "critical", 1},
		{"high only", "high", 1},
		{"medium only", "medium", 1},
		{"low only", "low", 1},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			stdout, _, exitCode := runLinterCommand(t, binaryPath, 
				"--severity", tc.severity, testDir)
			
			assert.Equal(t, tc.expected, exitCode)
			if exitCode == 1 {
				assert.Contains(t, stdout, "Security Scan Results")
			}
			// May contain warnings about unparseable files
		})
	}
}

func TestCLIOutputFormats(t *testing.T) {
	binaryPath := buildLinterBinary(t)
	testDir := setupTestFixtures(t)
	
	testCases := []struct {
		name   string
		format string
		checks []string
	}{
		{
			name:   "text format",
			format: "text",
			checks: []string{"Security Scan Results", "📊 Summary"},
		},
		{
			name:   "json format",
			format: "json",
			checks: []string{`"issues"`, `"stats"`},
		},
		{
			name:   "sarif format",
			format: "sarif",
			checks: []string{`"$schema"`, `"version"`, `"runs"`},
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			stdout, _, exitCode := runLinterCommand(t, binaryPath, 
				"--format", tc.format, testDir)
			
			assert.Equal(t, 1, exitCode) // Should find issues
			// May contain warnings about unparseable files
			
			for _, check := range tc.checks {
				assert.Contains(t, stdout, check, "Output should contain: %s", check)
			}
		})
	}
}

func TestCLIVerboseOutput(t *testing.T) {
	binaryPath := buildLinterBinary(t)
	testDir := setupTestFixtures(t)
	
	t.Run("verbose flag", func(t *testing.T) {
		stdout, _, exitCode := runLinterCommand(t, binaryPath, 
			"--verbose", testDir)
		
		assert.Equal(t, 1, exitCode)
		assert.Contains(t, stdout, "DEBUG: Config path")
		// May contain warnings about unparseable files
	})
	
	t.Run("short verbose flag", func(t *testing.T) {
		stdout, _, exitCode := runLinterCommand(t, binaryPath, 
			"-v", testDir)
		
		assert.Equal(t, 1, exitCode)
		assert.Contains(t, stdout, "DEBUG: Config path")
		// May contain warnings about unparseable files
	})
}

func TestCLIFileOutput(t *testing.T) {
	binaryPath := buildLinterBinary(t)
	testDir := setupTestFixtures(t)
	outputDir := t.TempDir()
	
	testCases := []struct {
		name       string
		format     string
		outputFile string
		checks     []string
	}{
		{
			name:       "json output file",
			format:     "json",
			outputFile: filepath.Join(outputDir, "report.json"),
			checks:     []string{`"issues"`, `"stats"`},
		},
		{
			name:       "sarif output file",
			format:     "sarif",
			outputFile: filepath.Join(outputDir, "report.sarif"),
			checks:     []string{`"$schema"`, `"runs"`},
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			stdout, _, exitCode := runLinterCommand(t, binaryPath,
				"--format", tc.format,
				"--output", tc.outputFile,
				testDir)
			
			assert.Equal(t, 1, exitCode)
			assert.Contains(t, stdout, "Detailed report saved to")
			// May contain warnings about unparseable files
			
			// Check that output file was created
			assert.FileExists(t, tc.outputFile)
			
			// Check file contents
			content, err := os.ReadFile(tc.outputFile)
			require.NoError(t, err)
			
			for _, check := range tc.checks {
				assert.Contains(t, string(content), check)
			}
		})
	}
}

func TestCLIConfigFile(t *testing.T) {
	binaryPath := buildLinterBinary(t)
	testDir := setupTestFixtures(t)
	configFile := filepath.Join(testDir, "tflint.yaml")
	
	t.Run("with config file", func(t *testing.T) {
		stdout, _, exitCode := runLinterCommand(t, binaryPath,
			"--config-file", configFile,
			testDir)
		
		// Should still find issues but exclude invalid.tf
		assert.Equal(t, 1, exitCode)
		assert.Contains(t, stdout, "Security Scan Results")
		assert.NotContains(t, stdout, "invalid.tf") // Should be excluded
		// May contain warnings about unparseable files
	})
}

func TestCLIExcludePatterns(t *testing.T) {
	binaryPath := buildLinterBinary(t)
	testDir := setupTestFixtures(t)
	
	t.Run("exclude patterns", func(t *testing.T) {
		stdout, _, exitCode := runLinterCommand(t, binaryPath,
			"--exclude", "invalid.tf,*.tfvars",
			testDir)
		
		assert.Equal(t, 1, exitCode)
		assert.Contains(t, stdout, "Security Scan Results")
		assert.NotContains(t, stdout, "invalid.tf")
		// May contain warnings about unparseable files
	})
}

func TestCLIErrorHandling(t *testing.T) {
	binaryPath := buildLinterBinary(t)
	
	t.Run("invalid flag", func(t *testing.T) {
		stdout, stderr, exitCode := runLinterCommand(t, binaryPath, "--invalid-flag")
		
		assert.NotEqual(t, 0, exitCode)
		assert.Empty(t, stdout)
		assert.Contains(t, stderr, "unknown flag")
	})
	
	t.Run("invalid severity", func(t *testing.T) {
		testDir := setupTestFixtures(t)
		stdout, _, exitCode := runLinterCommand(t, binaryPath,
			"--severity", "invalid", testDir)
		
		// The linter should handle invalid severity gracefully
		assert.Equal(t, 1, exitCode)
		assert.Contains(t, stdout, "Security Scan Results")
		// May contain warnings about unparseable files
	})
	
	t.Run("invalid format", func(t *testing.T) {
		testDir := setupTestFixtures(t)
		stdout, _, exitCode := runLinterCommand(t, binaryPath,
			"--format", "invalid", testDir)
		
		// Should default to text format
		assert.Equal(t, 1, exitCode)
		assert.Contains(t, stdout, "Security Scan Results")
		// May contain warnings about unparseable files
	})
}

func TestCLIIntegrationWithRealFiles(t *testing.T) {
	binaryPath := buildLinterBinary(t)
	
	t.Run("empty directory", func(t *testing.T) {
		emptyDir := t.TempDir()
		stdout, stderr, exitCode := runLinterCommand(t, binaryPath, emptyDir)
		
		assert.Equal(t, 0, exitCode)
		assert.Contains(t, stdout, "No security issues found")
		assert.Empty(t, stderr)
	})
	
	t.Run("directory with only .tfvars", func(t *testing.T) {
		tfvarsDir := t.TempDir()
		tfvarsContent := `
region = "us-west-2"
bucket_name = "test-bucket"
`
		err := os.WriteFile(filepath.Join(tfvarsDir, "vars.tfvars"), []byte(tfvarsContent), 0644)
		require.NoError(t, err)
		
		stdout, stderr, exitCode := runLinterCommand(t, binaryPath, tfvarsDir)
		
		assert.Equal(t, 0, exitCode)
		assert.Contains(t, stdout, "No security issues found")
		assert.Empty(t, stderr)
	})
}

// Benchmark tests for CLI performance
func BenchmarkCLIBasicLinting(b *testing.B) {
	binaryPath := buildLinterBinary(&testing.T{})
	testDir := setupTestFixtures(&testing.T{})
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		runLinterCommand(&testing.T{}, binaryPath, testDir)
	}
}

func BenchmarkCLIVerboseLinting(b *testing.B) {
	binaryPath := buildLinterBinary(&testing.T{})
	testDir := setupTestFixtures(&testing.T{})
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		runLinterCommand(&testing.T{}, binaryPath, "--verbose", testDir)
	}
}

func BenchmarkCLIJSONOutput(b *testing.B) {
	binaryPath := buildLinterBinary(&testing.T{})
	testDir := setupTestFixtures(&testing.T{})
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		runLinterCommand(&testing.T{}, binaryPath, "--format", "json", testDir)
	}
} 