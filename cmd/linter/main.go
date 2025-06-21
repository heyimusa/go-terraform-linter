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
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "tflint",
		Short: "A security-focused Terraform linter",
		Long: `A fast and comprehensive Terraform linter that focuses on security best practices,
resource misconfigurations, and infrastructure vulnerabilities.`,
		RunE: runLint,
	}

	rootCmd.Flags().StringVarP(&configPath, "config", "c", ".", "Path to Terraform configuration directory")
	rootCmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output file for detailed report (JSON)")
	rootCmd.Flags().StringVarP(&severity, "severity", "s", "all", "Minimum severity level (low, medium, high, critical, all)")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runLint(cmd *cobra.Command, args []string) error {
	linter := linter.NewLinter()
	
	// Configure linter
	linter.SetSeverity(severity)
	linter.SetVerbose(verbose)
	
	// Run linting
	report, err := linter.Lint(configPath)
	if err != nil {
		return fmt.Errorf("linting failed: %w", err)
	}
	
	// Display results
	report.PrintSummary()
	
	// Save detailed report if requested
	if outputPath != "" {
		if err := report.SaveToFile(outputPath); err != nil {
			return fmt.Errorf("failed to save report: %w", err)
		}
		fmt.Printf("\nDetailed report saved to: %s\n", outputPath)
	}
	
	// Exit with error code if issues found
	if report.HasIssues() {
		os.Exit(1)
	}
	
	return nil
} 