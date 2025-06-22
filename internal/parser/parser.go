package parser

import (
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/heyimusa/go-terraform-linter/internal/types"
)

type Config struct {
	Blocks []types.Block
}

type Block struct {
	Type       string
	Labels     []string
	Attributes map[string]Attribute
	Blocks     []Block
	Range      hcl.Range
}

type Attribute struct {
	Name     string
	Value    interface{}
	RawValue string
	Range    hcl.Range
}

type Parser struct {
	parser *hclparse.Parser
}

func NewParser() *Parser {
	return &Parser{
		parser: hclparse.NewParser(),
	}
}

func (p *Parser) ParseFile(filename string) (*Config, error) {
	// Read file content
	src, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Parse based on file extension
	var file *hcl.File
	var diags hcl.Diagnostics

	if strings.HasSuffix(filename, ".tf") || strings.HasSuffix(filename, ".tfvars") {
		file, diags = p.parser.ParseHCL(src, filename)
	} else if strings.HasSuffix(filename, ".tf.json") {
		file, diags = p.parser.ParseJSON(src, filename)
	} else {
		return nil, fmt.Errorf("unsupported file type: %s", filename)
	}

	if diags.HasErrors() {
		return nil, fmt.Errorf("parsing errors: %v", diags)
	}

	// Extract blocks and attributes
	config := &Config{}
	config.Blocks = p.extractBlocks(file.Body)

	// Remove debug output for production

	return config, nil
}

func (p *Parser) extractBlocks(body hcl.Body) []types.Block {
	var blocks []types.Block

	// Try to parse as HCL syntax first
	if syntaxBody, ok := body.(*hclsyntax.Body); ok {
		return p.extractBlocksFromSyntax(syntaxBody)
	}

	// Fallback to generic parsing
	content, _, diags := body.PartialContent(&hcl.BodySchema{})
	if diags.HasErrors() {
		return blocks
	}

	// Process each block
	for _, block := range content.Blocks {
		tfBlock := types.Block{
			Type:       block.Type,
			Labels:     block.Labels,
			Attributes: make(map[string]types.Attribute),
			Range:      block.DefRange,
		}

		// Extract attributes from the block
		attrs, _ := block.Body.JustAttributes()
		for name, attr := range attrs {
			val, _ := attr.Expr.Value(nil)
			rawValue := extractRawValue(val)
			tfBlock.Attributes[name] = types.Attribute{
				Name:     name,
				Value:    val,
				RawValue: rawValue,
				Range:    attr.Range,
			}
		}

		// Extract nested blocks
		tfBlock.Blocks = p.extractBlocks(block.Body)
		blocks = append(blocks, tfBlock)
	}

	return blocks
}

func (p *Parser) extractBlocksFromSyntax(body *hclsyntax.Body) []types.Block {
	var blocks []types.Block

	for _, block := range body.Blocks {
		tfBlock := types.Block{
			Type:       block.Type,
			Labels:     block.Labels,
			Attributes: make(map[string]types.Attribute),
			Range:      block.DefRange(),
		}

		// Extract attributes
		for name, attr := range block.Body.Attributes {
			val, _ := attr.Expr.Value(nil)
			rawValue := extractRawValue(val)
			tfBlock.Attributes[name] = types.Attribute{
				Name:     name,
				Value:    val,
				RawValue: rawValue,
				Range:    attr.SrcRange,
			}
		}

		// Extract nested blocks
		tfBlock.Blocks = p.extractBlocksFromSyntax(block.Body)
		blocks = append(blocks, tfBlock)
	}

	return blocks
} 

// extractRawValue extracts a clean string representation from cty.Value
func extractRawValue(val cty.Value) string {
	if val.IsNull() {
		return "null"
	}
	
	switch val.Type() {
	case cty.String:
		return val.AsString()
	case cty.Number:
		num := val.AsBigFloat()
		if num.IsInt() {
			i, _ := num.Int64()
			return fmt.Sprintf("%d", i)
		}
		f, _ := num.Float64()
		return fmt.Sprintf("%g", f)
	case cty.Bool:
		if val.True() {
			return "true"
		}
		return "false"
	default:
		// For complex types (maps, lists, etc.), return a formatted representation
		return fmt.Sprintf("%#v", val)
	}
}