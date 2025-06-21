package linter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/heyimusa/go-terraform-linter/internal/parser"
	"github.com/heyimusa/go-terraform-linter/internal/report"
	"github.com/heyimusa/go-terraform-linter/internal/rules"
	"github.com/heyimusa/go-terraform-linter/internal/rules/custom"
	yaml "gopkg.in/yaml.v3"
	"github.com/heyimusa/go-terraform-linter/internal/types"
)

type Linter struct {
	severity string
	verbose  bool
	parser   *parser.Parser
	rules    *rules.RuleEngine

	// New fields for config/customization
	excludePatterns []string
	configFile      string
	customRules     []rules.Rule
	severityOverrides map[string]string
	// Plugin system stub
	plugins         []interface{} // TODO: Define plugin interface
}

func NewLinter() *Linter {
	return &Linter{
		severity: "all",
		verbose:  false,
		parser:   parser.NewParser(),
		rules:    rules.NewRuleEngine(),
		excludePatterns: []string{},
		configFile:      "",
		customRules:     []rules.Rule{},
		severityOverrides: map[string]string{},
		plugins:         []interface{}{},
	}
}

// Add methods to set config/customization
func (l *Linter) SetExcludePatterns(patterns []string) {
	l.excludePatterns = patterns
}
func (l *Linter) SetConfigFile(path string) {
	l.configFile = path
}
func (l *Linter) SetSeverityOverrides(overrides map[string]string) {
	l.severityOverrides = overrides
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
	
	// --- Load config file for custom rules, severity overrides, exclude patterns ---
	if l.configFile != "" {
		data, err := os.ReadFile(l.configFile)
		if err == nil {
			var cfg struct {
				Exclude []string `yaml:"exclude" json:"exclude"`
				Severity map[string]string `yaml:"severity" json:"severity"`
				CustomRules []custom.CustomRule `yaml:"custom_rules" json:"custom_rules"`
			}
			if strings.HasSuffix(l.configFile, ".json") {
				_ = json.Unmarshal(data, &cfg)
			} else {
				_ = yaml.Unmarshal(data, &cfg)
			}
			l.excludePatterns = cfg.Exclude
			l.severityOverrides = cfg.Severity
			l.customRules = []rules.Rule{}
			for _, cr := range cfg.CustomRules {
				l.customRules = append(l.customRules, cr)
			}
		}
	}
	
	// Find all Terraform files
	tfFiles, err := l.findTerraformFiles(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to find Terraform files: %w", err)
	}
	
	if l.verbose {
		fmt.Printf("Found %d Terraform files to analyze\n", len(tfFiles))
	}

	// Exclude files matching patterns
	filteredFiles := []string{}
	for _, file := range tfFiles {
		excluded := false
		for _, pat := range l.excludePatterns {
			if strings.Contains(file, pat) {
				excluded = true
				break
			}
		}
		if !excluded {
			filteredFiles = append(filteredFiles, file)
		}
	}
	tfFiles = filteredFiles
	
	// --- Parallel file analysis ---
	type result struct {
		file   string
		issues []types.Issue
		err    error
	}
	results := make(chan result, len(tfFiles))
	
	for _, file := range tfFiles {
		go func(file string) {
			// --- Caching stub: check if file is unchanged, skip if so ---
			// TODO: Implement caching based on file hash/timestamp
			
			// Parse the file
			config, err := l.parser.ParseFile(file)
			if err != nil {
				results <- result{file, nil, err}
				return
			}
			
			// Run security rules
			issues := l.rules.RunRules(config, l.severity)
			// Run custom rules
			for _, cr := range l.customRules {
				issues = append(issues, cr.Check(config)...)
			}
			results <- result{file, issues, nil}
		}(file)
	}
	
	// Collect results
	parseErrors := 0
	for i := 0; i < len(tfFiles); i++ {
		res := <-results
		if res.err != nil {
			parseErrors++
			report.AddError(res.file, "PARSE_ERROR", "Failed to parse Terraform file", res.err.Error(), "critical")
			continue
		}
		for _, issue := range res.issues {
			report.AddIssue(res.file, issue.Rule, issue.Message, issue.Description, issue.Severity, issue.Line)
		}
	}
	if parseErrors > 0 {
		fmt.Fprintf(os.Stderr, "Warning: %d file(s) could not be parsed. Partial results shown.\n", parseErrors)
	}
	
	// Apply severity overrides after collecting issues
	for i, issue := range report.Issues {
		if sev, ok := l.severityOverrides[issue.Rule]; ok {
			report.Issues[i].Severity = sev
		}
	}
	
	// --- Incremental scan stub: only scan changed files ---
	// TODO: Implement incremental scanning for large codebases
	
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
				if l.verbose {
					fmt.Printf("DEBUG: Found Terraform file: %s\n", path)
				}
			}
		}
		
		return nil
	})
	
	if l.verbose {
		fmt.Printf("DEBUG: Total Terraform files found: %d\n", len(files))
	}
	
	return files, err
} 