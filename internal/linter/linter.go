package linter

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/heyimusa/go-terraform-linter/internal/parser"
	"github.com/heyimusa/go-terraform-linter/internal/report"
	"github.com/heyimusa/go-terraform-linter/internal/rules"
)

type Linter struct {
	severity string
	verbose  bool
	parser   *parser.Parser
	rules    *rules.RuleEngine
}

func NewLinter() *Linter {
	return &Linter{
		severity: "all",
		verbose:  false,
		parser:   parser.NewParser(),
		rules:    rules.NewRuleEngine(),
	}
}

func (l *Linter) SetSeverity(severity string) {
	l.severity = severity
}

func (l *Linter) SetVerbose(verbose bool) {
	l.verbose = verbose
}

func (l *Linter) Lint(configPath string) (*report.Report, error) {
	report := report.NewReport()
	
	// Validate path
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("configuration path does not exist: %s", configPath)
	}
	
	// Find all Terraform files
	tfFiles, err := l.findTerraformFiles(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to find Terraform files: %w", err)
	}
	
	if l.verbose {
		fmt.Printf("Found %d Terraform files to analyze\n", len(tfFiles))
	}
	
	// Parse each file
	for _, file := range tfFiles {
		if l.verbose {
			fmt.Printf("Analyzing: %s\n", file)
		}
		
		// Parse the file
		config, err := l.parser.ParseFile(file)
		if err != nil {
			report.AddError(file, "PARSE_ERROR", "Failed to parse Terraform file", err.Error(), "critical")
			continue
		}
		
		// Run security rules
		issues := l.rules.RunRules(config, l.severity)
		for _, issue := range issues {
			report.AddIssue(file, issue.Rule, issue.Message, issue.Description, issue.Severity, issue.Line)
		}
	}
	
	return report, nil
}

func (l *Linter) findTerraformFiles(root string) ([]string, error) {
	var files []string
	
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		// Skip hidden directories
		if info.IsDir() && strings.HasPrefix(info.Name(), ".") && path != root {
			return filepath.SkipDir
		}
		
		// Check for Terraform files
		if !info.IsDir() {
			ext := filepath.Ext(path)
			if ext == ".tf" || ext == ".tfvars" || strings.HasSuffix(path, ".tf.json") {
				files = append(files, path)
			}
		}
		
		return nil
	})
	
	return files, err
} 