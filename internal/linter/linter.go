package linter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/heyimusa/go-terraform-linter/internal/parser"
	"github.com/heyimusa/go-terraform-linter/internal/report"
	"github.com/heyimusa/go-terraform-linter/internal/rules"
	"github.com/heyimusa/go-terraform-linter/internal/rules/custom"
	yaml "gopkg.in/yaml.v3"
	"github.com/heyimusa/go-terraform-linter/internal/types"
	"github.com/heyimusa/go-terraform-linter/internal/cache"
	"github.com/heyimusa/go-terraform-linter/internal/logger"
	"github.com/heyimusa/go-terraform-linter/internal/validation"
)

type Linter struct {
	severity string
	verbose  bool
	parser   *parser.Parser
	logger   *logger.Logger
	cache    *cache.Cache
	validator *validation.RuleValidator
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
	log := logger.NewLogger(logger.INFO, nil)
	return &Linter{
		severity: "all",
		verbose:  false,
		parser:   parser.NewParser(),
		logger:   log,
		cache:    cache.NewCache(".tflint-cache", true),
		validator: validation.NewRuleValidator(),
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
	l.logger.Info("Starting lint scan", map[string]interface{}{"path": configPath})
	start := time.Now()
	
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
		l.logger.Error("Failed to find Terraform files", map[string]interface{}{"error": err.Error()})
		return nil, fmt.Errorf("failed to find Terraform files: %w", err)
	}
	
	if l.verbose {
		l.logger.Debug(fmt.Sprintf("Found %d Terraform files to analyze", len(tfFiles)))
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
			// Caching: skip unchanged files
			changed, err := l.cache.IsFileChanged(file)
			if err != nil {
				l.logger.Warn("Cache check failed", map[string]interface{}{"file": file, "error": err.Error()})
			}
			if !changed {
				cachedIssues, ok := l.cache.GetCachedIssues(file)
				if ok {
					// Convert cached issues to types.Issue
					var issues []types.Issue
					for _, ci := range cachedIssues {
						issues = append(issues, types.Issue{
							Rule: ci.Rule, Message: ci.Message, Severity: ci.Severity, Line: ci.Line, Description: ci.Description,
						})
					}
					results <- result{file, issues, nil}
					return
				}
			}
			// Parse the file
			config, err := l.parser.ParseFile(file)
			if err != nil {
				l.logger.Error("Parse error", map[string]interface{}{"file": file, "error": err.Error()})
				results <- result{file, nil, err}
				return
			}
			
			// Run security rules
			issues := l.rules.RunRules(config, l.severity)
			// Run custom rules
			for _, cr := range l.customRules {
				issues = append(issues, cr.Check(config)...)
			}
			// Validate issues
			var validated []types.Issue
			var cached []cache.CachedIssue
			for _, issue := range issues {
				vres := l.validator.ValidateIssue(issue, config)
				if vres.IsValid && vres.Confidence >= 0.5 {
					validated = append(validated, issue)
					cached = append(cached, cache.CachedIssue{
						Rule: issue.Rule, Message: issue.Message, Severity: issue.Severity, Line: issue.Line, Description: issue.Description,
					})
				} else if l.verbose {
					l.logger.Debug("Filtered low-confidence issue", map[string]interface{}{"rule": issue.Rule, "file": file, "reason": vres.Reason})
				}
			}
			// Store in cache
			_ = l.cache.StoreFileResult(file, cached)
			results <- result{file, validated, nil}
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
		l.logger.Warn("Some files could not be parsed", map[string]interface{}{"count": parseErrors})
		fmt.Fprintf(os.Stderr, "Warning: %d file(s) could not be parsed. Partial results shown.\n", parseErrors)
	}
	
	// Apply severity overrides after collecting issues
	for i, issue := range report.Issues {
		if sev, ok := l.severityOverrides[issue.Rule]; ok {
			report.Issues[i].Severity = sev
		}
	}
	
	l.logger.Info("Scan complete", map[string]interface{}{"duration": time.Since(start).String(), "issues": len(report.Issues)})
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