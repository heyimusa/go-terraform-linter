package main

import (
	"fmt"
	"os"

	"github.com/heyimusa/go-terraform-linter/internal/linter"
	"github.com/spf13/cobra"
)

var (
	// Build-time variables (set via ldflags)
	version    = "dev"
	commitHash = "unknown"
	buildTime  = "unknown"

	// CLI flags
	configPath  string
	outputPath  string
	severity    string
	verbose     bool
	format      string
	showVersion bool

	excludePatterns   []string
	configFile        string
	severityOverrides map[string]string
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "go-terraform-linter [path]",
		Short: "A security-focused Terraform linter",
		Long: `A fast and comprehensive Terraform linter that focuses on security best practices,
resource misconfigurations, and infrastructure vulnerabilities.`,
		Args: cobra.MaximumNArgs(1),
		RunE: runLint,
	}

	rootCmd.Flags().StringVarP(&configPath, "config", "c", ".", "Path to Terraform configuration directory")
	rootCmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file for detailed report (JSON/SARIF/HTML)")
	rootCmd.Flags().StringVarP(&severity, "severity", "s", "all", "Minimum severity level (low, medium, high, critical, all)")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text, json, sarif, html")
	rootCmd.Flags().StringSliceVar(&excludePatterns, "exclude", []string{}, "Exclude files matching these patterns (comma-separated)")
	rootCmd.Flags().StringVar(&configFile, "config-file", "", "Path to YAML/JSON config file for custom rules and settings")
	rootCmd.Flags().BoolVar(&showVersion, "version", false, "Show version information")

	// Add version command
	var versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Run: func(cmd *cobra.Command, args []string) {
			printVersion()
		},
	}
	rootCmd.AddCommand(versionCmd)

	// Handle version flag
	rootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		if showVersion {
			printVersion()
			os.Exit(0)
		}
	}

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func printVersion() {
	fmt.Printf("go-terraform-linter version %s\n", version)
	fmt.Printf("Git commit: %s\n", commitHash)
	fmt.Printf("Built: %s\n", buildTime)
	fmt.Printf("Go version: %s\n", "go1.21")
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
