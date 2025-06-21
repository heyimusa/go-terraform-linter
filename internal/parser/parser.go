package parser

import (
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

type Config struct {
	Blocks []Block
}

type Block struct {
	Type       string
	Labels     []string
	Attributes map[string]Attribute
	Blocks     []Block
	Range      hcl.Range
}

type Attribute struct {
	Name  string
	Value interface{}
	Range hcl.Range
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

	if strings.HasSuffix(filename, ".tf") {
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

	// Debug output
	fmt.Printf("DEBUG: Parsed %d blocks\n", len(config.Blocks))
	for i, block := range config.Blocks {
		fmt.Printf("DEBUG: Block %d: Type=%s, Labels=%v, Attributes=%d\n", 
			i, block.Type, block.Labels, len(block.Attributes))
		for name, attr := range block.Attributes {
			fmt.Printf("DEBUG:   Attribute: %s = %v\n", name, attr.Value)
		}
	}

	return config, nil
}

func (p *Parser) extractBlocks(body hcl.Body) []Block {
	var blocks []Block

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
		tfBlock := Block{
			Type:       block.Type,
			Labels:     block.Labels,
			Attributes: make(map[string]Attribute),
			Range:      block.DefRange,
		}

		// Extract attributes from the block
		attrs, _ := block.Body.JustAttributes()
		for name, attr := range attrs {
			val, _ := attr.Expr.Value(nil)
			tfBlock.Attributes[name] = Attribute{
				Name:  name,
				Value: val,
				Range: attr.Range,
			}
		}

		// Extract nested blocks
		tfBlock.Blocks = p.extractBlocks(block.Body)
		blocks = append(blocks, tfBlock)
	}

	return blocks
}

func (p *Parser) extractBlocksFromSyntax(body *hclsyntax.Body) []Block {
	var blocks []Block

	for _, block := range body.Blocks {
		tfBlock := Block{
			Type:       block.Type,
			Labels:     block.Labels,
			Attributes: make(map[string]Attribute),
			Range:      block.SrcRange,
		}

		// Extract attributes
		for name, attr := range block.Body.Attributes {
			val, _ := attr.Expr.Value(nil)
			tfBlock.Attributes[name] = Attribute{
				Name:  name,
				Value: val,
				Range: attr.SrcRange,
			}
		}

		// Extract nested blocks
		tfBlock.Blocks = p.extractBlocksFromSyntax(block.Body)
		blocks = append(blocks, tfBlock)
	}

	return blocks
} 