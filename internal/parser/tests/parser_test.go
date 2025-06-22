package tests

import (
	"os"
	"testing"

	"github.com/heyimusa/go-terraform-linter/internal/parser"
	"github.com/heyimusa/go-terraform-linter/internal/types"
)

func TestParserBasicFunctionality(t *testing.T) {
	p := parser.NewParser()
	
	tests := []struct {
		name    string
		content string
		wantErr bool
	}{
		{
			name: "valid basic terraform config",
			content: `
resource "aws_instance" "test" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
  
  tags = {
    Name = "test-instance"
  }
}
`,
			wantErr: false,
		},
		{
			name: "valid provider config",
			content: `
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = "us-west-2"
}
`,
			wantErr: false,
		},
		{
			name: "valid variables",
			content: `
variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.micro"
}

variable "environment" {
  description = "Environment name"
  type        = string
}
`,
			wantErr: false,
		},
		{
			name: "empty terraform file",
			content: `
# This is an empty terraform file with just comments
`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary file
			tmpFile := createTempTerraformFile(t, tt.content)
			defer os.Remove(tmpFile)
			
			config, err := p.ParseFile(tmpFile)
			
			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}
			
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}
			
			if config == nil {
				t.Errorf("Expected config but got nil")
				return
			}
			
			// Basic validation of parsed content - only check for blocks if not empty file
			if tt.name != "empty terraform file" && len(config.Blocks) == 0 {
				t.Errorf("Expected at least one block, got %d", len(config.Blocks))
			}
		})
	}
}

func TestParserFileTypes(t *testing.T) {
	p := parser.NewParser()
	
	tests := []struct {
		name     string
		filename string
		content  string
		wantErr  bool
	}{
		{
			name:     "terraform file",
			filename: "test.tf",
			content: `
resource "aws_instance" "test" {
  ami = "ami-12345678"
}
`,
			wantErr: false,
		},
		{
			name:     "terraform variables file",
			filename: "test.tfvars",
			content: `
instance_type = "t3.micro"
environment   = "test"
`,
			wantErr: false,
		},
		{
			name:     "terraform JSON file",
			filename: "test.tf.json",
			content: `{
  "resource": {
    "aws_instance": {
      "test": {
        "ami": "ami-12345678",
        "instance_type": "t3.micro"
      }
    }
  }
}`,
			wantErr: false,
		},
		{
			name:     "unsupported file type",
			filename: "test.txt",
			content:  "This is not terraform",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary file with specific extension
			tmpFile := createTempFileWithName(t, tt.filename, tt.content)
			defer os.Remove(tmpFile)
			
			_, err := p.ParseFile(tmpFile)
			
			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}
			
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestParserBlockExtraction(t *testing.T) {
	p := parser.NewParser()
	
	content := `
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = "us-west-2"
}

resource "aws_instance" "test" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
  
  tags = {
    Name = "test-instance"
    Environment = "test"
  }
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]
  
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }
}
`
	
	tmpFile := createTempTerraformFile(t, content)
	defer os.Remove(tmpFile)
	
	config, err := p.ParseFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to parse file: %v", err)
	}
	
	// Test block extraction
	if len(config.Blocks) < 4 {
		t.Errorf("Expected at least 4 blocks (terraform, provider, resource, data), got %d", len(config.Blocks))
	}
	
	// Test specific block types
	hasTerraform := false
	hasProvider := false
	hasResource := false
	hasData := false
	
	for _, block := range config.Blocks {
		switch block.Type {
		case "terraform":
			hasTerraform = true
		case "provider":
			hasProvider = true
		case "resource":
			hasResource = true
		case "data":
			hasData = true
		}
	}
	
	if !hasTerraform {
		t.Error("Expected terraform block not found")
	}
	if !hasProvider {
		t.Error("Expected provider block not found")
	}
	if !hasResource {
		t.Error("Expected resource block not found")
	}
	if !hasData {
		t.Error("Expected data block not found")
	}
}

func TestParserAttributeExtraction(t *testing.T) {
	p := parser.NewParser()
	
	content := `
resource "aws_instance" "test" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
  count         = 2
  
  tags = {
    Name = "test-instance"
    Environment = "test"
  }
}
`
	
	tmpFile := createTempTerraformFile(t, content)
	defer os.Remove(tmpFile)
	
	config, err := p.ParseFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to parse file: %v", err)
	}
	
	// Find the resource block
	var resourceBlock *types.Block
	for i := range config.Blocks {
		if config.Blocks[i].Type == "resource" {
			resourceBlock = &config.Blocks[i]
			break
		}
	}
	
	if resourceBlock == nil {
		t.Fatal("Resource block not found")
	}
	
	// Test attribute extraction
	expectedAttrs := map[string]string{
		"ami":           "ami-12345678",
		"instance_type": "t3.micro",
		"count":         "2",
	}
	
	for attrName, expectedValue := range expectedAttrs {
		if attr, exists := resourceBlock.Attributes[attrName]; exists {
			actualValue := attr.RawValue
			if actualValue != expectedValue {
				t.Errorf("Attribute %s: expected %s, got %s", attrName, expectedValue, actualValue)
			}
		} else {
			t.Errorf("Expected attribute %s not found", attrName)
		}
	}
}

func TestParserErrorRecovery(t *testing.T) {
	p := parser.NewParser()
	
	// Test with multiple files, some with errors
	files := []struct {
		name    string
		content string
		hasErr  bool
	}{
		{
			name: "valid.tf",
			content: `
resource "aws_instance" "valid" {
  ami = "ami-12345678"
}
`,
			hasErr: false,
		},
		{
			name: "invalid.tf",
			content: `
resource "aws_instance" "invalid" {
  ami = "ami-12345678"
  # Missing closing brace
`,
			hasErr: true,
		},
		{
			name: "another_valid.tf",
			content: `
resource "aws_s3_bucket" "test" {
  bucket = "test-bucket"
}
`,
			hasErr: false,
		},
	}
	
	// Create temporary files
	var tmpFiles []string
	for _, file := range files {
		tmpFile := createTempFileWithName(t, file.name, file.content)
		tmpFiles = append(tmpFiles, tmpFile)
		defer os.Remove(tmpFile)
	}
	
	// Parse each file individually to test error recovery
	for i, file := range files {
		t.Run(file.name, func(t *testing.T) {
			_, err := p.ParseFile(tmpFiles[i])
			
			if file.hasErr && err == nil {
				t.Errorf("Expected error for %s but got none", file.name)
			} else if !file.hasErr && err != nil {
				t.Errorf("Unexpected error for %s: %v", file.name, err)
			}
		})
	}
}

// Helper functions
func createTempTerraformFile(t *testing.T, content string) string {
	return createTempFileWithName(t, "test.tf", content)
}

func createTempFileWithName(t *testing.T, filename, content string) string {
	tmpFile := filename
	err := os.WriteFile(tmpFile, []byte(content), 0644)
	if err != nil {
		t.Fatalf("Failed to create temporary file: %v", err)
	}
	return tmpFile
} 