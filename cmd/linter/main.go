package main

import (
	"fmt"
	"os"

	"github.com/heyimusa/go-terraform-linter/internal/linter"
	"github.com/spf13/cobra"
)

var (
	configPath string
	outputPath string
	severity   string
	verbose    bool
	format     string

	excludePatterns []string
	configFile      string
	severityOverrides map[string]string
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "tflint [path]",
		Short: "A security-focused Terraform linter",
		Long: `A fast and comprehensive Terraform linter that focuses on security best practices,
resource misconfigurations, and infrastructure vulnerabilities.`,
		Args:  cobra.MaximumNArgs(1),
		RunE: runLint,
	}

	rootCmd.Flags().StringVarP(&configPath, "config", "c", ".", "Path to Terraform configuration directory")
	rootCmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file for detailed report (JSON/SARIF/HTML)")
	rootCmd.Flags().StringVarP(&severity, "severity", "s", "all", "Minimum severity level (low, medium, high, critical, all)")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text, json, sarif, html")
	rootCmd.Flags().StringSliceVar(&excludePatterns, "exclude", []string{}, "Exclude files matching these patterns (comma-separated)")
	rootCmd.Flags().StringVar(&configFile, "config-file", "", "Path to YAML/JSON config file for custom rules and settings")
	// For severity overrides, use config file or environment variable for now

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runLint(cmd *cobra.Command, args []string) error {
	// Use positional argument if provided, otherwise use flag
	if len(args) > 0 {
		configPath = args[0]
	}

	linter := linter.NewLinter()
	linter.SetSeverity(severity)
	linter.SetVerbose(verbose)
	linter.SetExcludePatterns(excludePatterns)
	linter.SetConfigFile(configFile)
	// Severity overrides from config file will be loaded in linter

	if verbose {
		fmt.Printf("DEBUG: Config path: %s\n", configPath)
	}

	report, err := linter.Lint(configPath)
	if err != nil {
		return fmt.Errorf("linting failed: %w", err)
	}

	// Display results in selected format
	switch format {
	case "json":
		report.PrintJSON()
	case "sarif":
		report.PrintSARIF()
	case "html":
		report.PrintHTML()
	default:
		report.PrintSummary()
	}

	// Save detailed report if requested
	if outputPath != "" {
		err := report.SaveToFileWithFormat(outputPath, format)
		if err != nil {
			return fmt.Errorf("failed to save report: %w", err)
		}
		fmt.Printf("\nDetailed report saved to: %s\n", outputPath)
	}

	if report.HasIssues() {
		os.Exit(1)
	}
	return nil
} 