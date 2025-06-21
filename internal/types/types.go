package types

import "github.com/hashicorp/hcl/v2"

// Issue represents a security issue found by a rule
type Issue struct {
	Rule        string
	Message     string
	Description string
	Severity    string
	Line        int
}

// Block represents a Terraform block (resource, module, etc.)
type Block struct {
	Type       string
	Labels     []string
	Attributes map[string]Attribute
	Blocks     []Block
	Range      hcl.Range
}

// Attribute represents a Terraform attribute
// Value is interface{} for flexibility, Range is the HCL source range
type Attribute struct {
	Name     string
	Value    interface{}
	RawValue string
	Range    hcl.Range
} 