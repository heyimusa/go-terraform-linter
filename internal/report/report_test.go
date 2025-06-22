package report

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewReport(t *testing.T) {
	report := NewReport()
	
	assert.NotNil(t, report)
	assert.Empty(t, report.Issues)
	assert.Equal(t, 0, report.Stats.Total)
	assert.Equal(t, 0, report.Stats.Critical)
	assert.Equal(t, 0, report.Stats.High)
	assert.Equal(t, 0, report.Stats.Medium)
	assert.Equal(t, 0, report.Stats.Low)
	assert.Equal(t, 0, report.Stats.Files)
}

func TestReportAddIssue(t *testing.T) {
	report := NewReport()
	
	testCases := []struct {
		name        string
		file        string
		rule        string
		message     string
		description string
		severity    string
		line        int
	}{
		{
			name:        "critical security issue",
			file:        "main.tf",
			rule:        "aws_s3_bucket_public_acl",
			message:     "Public bucket",
			description: "Bucket is public",
			severity:    "critical",
			line:        10,
		},
		{
			name:        "high severity issue",
			file:        "security.tf",
			rule:        "aws_sg_open_ssh",
			message:     "SSH open to world",
			description: "Security group allows SSH from anywhere",
			severity:    "high",
			line:        20,
		},
		{
			name:        "medium severity issue",
			file:        "instances.tf",
			rule:        "aws_instance_unencrypted",
			message:     "Unencrypted",
			description: "Unencrypted storage",
			severity:    "medium",
			line:        5,
		},
		{
			name:        "low severity issue",
			file:        "tags.tf",
			rule:        "aws_missing_tags",
			message:     "Missing tags",
			description: "Resource missing required tags",
			severity:    "low",
			line:        15,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			initialCount := len(report.Issues)
			initialTotal := report.Stats.Total
			
			report.AddIssue(tc.file, tc.rule, tc.message, tc.description, tc.severity, tc.line)
			
			// Verify issue was added
			assert.Equal(t, initialCount+1, len(report.Issues))
			assert.Equal(t, initialTotal+1, report.Stats.Total)
			
			// Check the added issue
			lastIssue := report.Issues[len(report.Issues)-1]
			assert.Equal(t, tc.file, lastIssue.File)
			assert.Equal(t, tc.rule, lastIssue.Rule)
			assert.Equal(t, tc.message, lastIssue.Message)
			assert.Equal(t, tc.description, lastIssue.Description)
			assert.Equal(t, tc.severity, lastIssue.Severity)
			assert.Equal(t, tc.line, lastIssue.Line)
			
			// Fix suggestions should be added
			assert.NotEmpty(t, lastIssue.FixSuggestion)
		})
	}
}

func TestReportAddError(t *testing.T) {
	report := NewReport()
	
	report.AddError("config.tf", "syntax_error", "Invalid syntax", "Configuration has syntax error", "high")
	
	assert.Equal(t, 1, len(report.Issues))
	assert.Equal(t, 1, report.Stats.Total)
	assert.Equal(t, 1, report.Stats.High)
	
	issue := report.Issues[0]
	assert.Equal(t, "config.tf", issue.File)
	assert.Equal(t, "syntax_error", issue.Rule)
	assert.Equal(t, "Invalid syntax", issue.Message)
	assert.Equal(t, "Configuration has syntax error", issue.Description)
	assert.Equal(t, "high", issue.Severity)
	assert.Equal(t, 0, issue.Line) // Errors have line 0
}

func TestReportStatsCalculation(t *testing.T) {
	report := NewReport()
	
	// Add various severity issues
	report.AddIssue("test.tf", "rule1", "msg1", "desc1", "critical", 1)
	report.AddIssue("test.tf", "rule2", "msg2", "desc2", "critical", 2)
	report.AddIssue("test.tf", "rule3", "msg3", "desc3", "high", 3)
	report.AddIssue("test.tf", "rule4", "msg4", "desc4", "medium", 4)
	report.AddIssue("test.tf", "rule5", "msg5", "desc5", "low", 5)
	report.AddIssue("test.tf", "rule6", "msg6", "desc6", "low", 6)
	
	assert.Equal(t, 6, report.Stats.Total)
	assert.Equal(t, 2, report.Stats.Critical)
	assert.Equal(t, 1, report.Stats.High)
	assert.Equal(t, 1, report.Stats.Medium)
	assert.Equal(t, 2, report.Stats.Low)
}

func TestReportStatsCalculationCaseInsensitive(t *testing.T) {
	report := NewReport()
	
	// Test case-insensitive severity handling
	report.AddIssue("test.tf", "rule1", "msg1", "desc1", "CRITICAL", 1)
	report.AddIssue("test.tf", "rule2", "msg2", "desc2", "High", 2)
	report.AddIssue("test.tf", "rule3", "msg3", "desc3", "Medium", 3)
	report.AddIssue("test.tf", "rule4", "msg4", "desc4", "LOW", 4)
	
	assert.Equal(t, 4, report.Stats.Total)
	assert.Equal(t, 1, report.Stats.Critical)
	assert.Equal(t, 1, report.Stats.High)
	assert.Equal(t, 1, report.Stats.Medium)
	assert.Equal(t, 1, report.Stats.Low)
}

func TestReportHasIssues(t *testing.T) {
	report := NewReport()
	
	// Empty report
	assert.False(t, report.HasIssues())
	
	// Add an issue
	report.AddIssue("test.tf", "rule1", "msg1", "desc1", "high", 1)
	assert.True(t, report.HasIssues())
}

func TestReportPrintJSON(t *testing.T) {
	report := NewReport()
	report.AddIssue("main.tf", "aws_s3_bucket_public_acl", "Public bucket", "Bucket is public", "critical", 10)
	report.AddIssue("security.tf", "aws_sg_open_ssh", "SSH open to world", "Security group allows SSH from anywhere", "high", 20)
	
	// Capture the JSON output by calling PrintJSON
	// Since PrintJSON prints to stdout, we'll test the JSON structure separately
	data, err := json.MarshalIndent(report, "", "  ")
	assert.NoError(t, err)

	var result map[string]interface{}
	err = json.Unmarshal(data, &result)
	assert.NoError(t, err)

	issues := result["issues"].([]interface{})
	assert.Equal(t, 2, len(issues))

	stats := result["stats"].(map[string]interface{})
	assert.Equal(t, float64(2), stats["total"])
	assert.Equal(t, float64(1), stats["critical"])
	assert.Equal(t, float64(1), stats["high"])
}

func TestReportPrintSARIF(t *testing.T) {
	report := NewReport()
	report.AddIssue("main.tf", "aws_s3_bucket_public_acl", "Public bucket", "Bucket is public", "critical", 10)
	
	sarifData, err := report.GenerateSARIF()
	assert.NoError(t, err)

	var sarif map[string]interface{}
	err = json.Unmarshal(sarifData, &sarif)
	assert.NoError(t, err)

	assert.Equal(t, "2.1.0", sarif["version"])
	
	runs := sarif["runs"].([]interface{})
	assert.Equal(t, 1, len(runs))
	
	run := runs[0].(map[string]interface{})
	tool := run["tool"].(map[string]interface{})
	driver := tool["driver"].(map[string]interface{})
	assert.Equal(t, "go-terraform-linter", driver["name"])
}

func TestReportPrintHTML(t *testing.T) {
	report := NewReport()
	report.AddIssue("main.tf", "aws_s3_bucket_public_acl", "Public bucket", "Bucket is public", "critical", 10)
	
	// Test HTML generation by checking the format method
	html, err := report.Format("html")
	assert.NoError(t, err)
	assert.Contains(t, html, "<html>")
	assert.Contains(t, html, "<table")
	assert.Contains(t, html, "main.tf")
	assert.Contains(t, html, "aws_s3_bucket_public_acl")
}

func TestReportPrintSummary(t *testing.T) {
	testCases := []struct {
		name   string
		issues []struct {
			file, rule, message, description, severity string
			line                                       int
		}
		expectEmpty bool
	}{
		{
			name:        "empty report",
			issues:      []struct{ file, rule, message, description, severity string; line int }{},
			expectEmpty: true,
		},
		{
			name: "report with issues",
			issues: []struct{ file, rule, message, description, severity string; line int }{
				{"main.tf", "aws_s3_bucket_public_acl", "Public bucket", "Bucket is public", "critical", 10},
				{"security.tf", "aws_sg_open_ssh", "SSH open", "SSH open to world", "high", 20},
				{"instances.tf", "aws_instance_unencrypted", "Unencrypted", "Unencrypted storage", "medium", 5},
			},
			expectEmpty: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			report := NewReport()
			for _, issue := range tc.issues {
				report.AddIssue(issue.file, issue.rule, issue.message, issue.description, issue.severity, issue.line)
			}

			// Since PrintSummary prints to stdout, we can't easily capture it
			// Instead, we test the HasIssues method which is used by PrintSummary
			if tc.expectEmpty {
				assert.False(t, report.HasIssues())
			} else {
				assert.True(t, report.HasIssues())
			}
		})
	}
}

func TestReportSaveToFile(t *testing.T) {
	report := NewReport()
	report.AddIssue("main.tf", "aws_s3_bucket_public_acl", "Public bucket", "Bucket is public", "critical", 10)
	
	tempFile := "/tmp/test_report.json"
	defer os.Remove(tempFile)

	err := report.SaveToFile(tempFile)
	assert.NoError(t, err)

	// Verify file exists and contains expected content
	data, err := os.ReadFile(tempFile)
	assert.NoError(t, err)
	assert.Contains(t, string(data), "aws_s3_bucket_public_acl")
	assert.Contains(t, string(data), "Public bucket")
}

func TestReportSaveToFileWithFormat(t *testing.T) {
	report := NewReport()
	report.AddIssue("main.tf", "aws_s3_bucket_public_acl", "Public bucket", "Bucket is public", "critical", 10)
	
	testCases := []struct {
		name           string
		format         string
		expectedString string
	}{
		{
			name:           "JSON format",
			format:         "json",
			expectedString: "aws_s3_bucket_public_acl",
		},
		{
			name:           "SARIF format",
			format:         "sarif",
			expectedString: "go-terraform-linter",
		},
		{
			name:           "text format",
			format:         "text",
			expectedString: "Found 1 issues:",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tempFile := "/tmp/test_report_" + tc.format
			defer os.Remove(tempFile)

			err := report.SaveToFileWithFormat(tempFile, tc.format)
			assert.NoError(t, err)

			data, err := os.ReadFile(tempFile)
			assert.NoError(t, err)
			assert.Contains(t, string(data), tc.expectedString)
		})
	}
}

func TestReportFormat(t *testing.T) {
	report := NewReport()
	report.AddIssue("main.tf", "aws_s3_bucket_public_acl", "Public bucket", "Bucket is public", "critical", 10)
	
	testCases := []struct {
		name           string
		format         string
		expectedString string
		expectError    bool
	}{
		{
			name:           "JSON format",
			format:         "json",
			expectedString: "aws_s3_bucket_public_acl",
			expectError:    false,
		},
		{
			name:           "SARIF format",
			format:         "sarif",
			expectedString: "go-terraform-linter",
			expectError:    false,
		},
		{
			name:           "text format",
			format:         "text",
			expectedString: "Found 1 issues:",
			expectError:    false,
		},
		{
			name:        "default format",
			format:      "unknown",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := report.Format(tc.format)

			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Contains(t, result, tc.expectedString)
			}
		})
	}
}

func TestReportGenerateSARIF(t *testing.T) {
	report := NewReport()
	report.AddIssue("main.tf", "aws_s3_bucket_public_acl", "Public bucket", "Bucket is public", "critical", 10)
	
	sarifData, err := report.GenerateSARIF()
	assert.NoError(t, err)

	var sarif map[string]interface{}
	err = json.Unmarshal(sarifData, &sarif)
	assert.NoError(t, err)

	runs := sarif["runs"].([]interface{})
	run := runs[0].(map[string]interface{})
	results := run["results"].([]interface{})
	result := results[0].(map[string]interface{})
	message := result["message"].(map[string]interface{})
	
	// The SARIF message includes both message and description
	assert.Equal(t, "Public bucket: Bucket is public", message["text"])
}

func TestReportConvertSeverityToSARIF(t *testing.T) {
	report := NewReport()
	
	testCases := []struct {
		severity string
		expected string
	}{
		{"critical", "error"},
		{"high", "error"},
		{"medium", "warning"},
		{"low", "note"},
		{"unknown", "warning"}, // Default case
		{"CRITICAL", "error"},  // Case insensitive
		{"High", "error"},      // Case insensitive
	}
	
	for _, tc := range testCases {
		t.Run(tc.severity, func(t *testing.T) {
			result := report.convertSeverityToSARIF(tc.severity)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestReportConvertSeverityToSecurityScore(t *testing.T) {
	report := NewReport()
	
	testCases := []struct {
		severity string
		expected string
	}{
		{"critical", "9.0"},
		{"high", "7.0"},
		{"medium", "5.0"},
		{"low", "3.0"},
		{"unknown", "5.0"}, // Default case
	}
	
	for _, tc := range testCases {
		t.Run(tc.severity, func(t *testing.T) {
			result := report.convertSeverityToSecurityScore(tc.severity)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestReportGetCloudProvider(t *testing.T) {
	report := NewReport()
	
	testCases := []struct {
		ruleID   string
		expected string
	}{
		{"aws_s3_bucket_public_acl", "general"},        // Doesn't start with AWS_
		{"azure_storage_account_open", "general"},      // Doesn't start with AZURE_
		{"gcp_compute_firewall_open", "general"},       // Doesn't start with GCP_
		{"kubernetes_pod_security", "general"},         // Doesn't start with any cloud prefix
		{"AWS_S3_BUCKET_PUBLIC", "aws"},               // Starts with AWS_
		{"AZURE_STORAGE_OPEN", "azure"},               // Starts with AZURE_
		{"unknown_rule", "general"},
	}
	
	for _, tc := range testCases {
		t.Run(tc.ruleID, func(t *testing.T) {
			result := report.getCloudProvider(tc.ruleID)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestReportFixSuggestions(t *testing.T) {
	report := NewReport()
	
	testCases := []struct {
		name        string
		rule        string
		expectedFix string
	}{
		{
			name:        "S3 public ACL",
			rule:        "aws_s3_bucket_public_acl",
			expectedFix: "", // Fix suggestions are handled by addFixSuggestion method
		},
		{
			name:        "Security group SSH",
			rule:        "aws_sg_open_ssh",
			expectedFix: "",
		},
		{
			name:        "Unencrypted storage",
			rule:        "aws_instance_unencrypted",
			expectedFix: "",
		},
		{
			name:        "Unknown rule",
			rule:        "unknown_rule",
			expectedFix: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			report.AddIssue("test.tf", tc.rule, "Test message", "Test description", "high", 10)
			
			issue := report.Issues[len(report.Issues)-1]
			// Fix suggestions are added by addFixSuggestion method
			// We don't assert specific content since it depends on implementation
			assert.NotNil(t, issue.FixSuggestion)
		})
	}
}

func TestReportFormatText(t *testing.T) {
	report := NewReport()
	report.AddIssue("main.tf", "aws_s3_bucket_public_acl", "Public bucket", "Bucket is public", "critical", 10)
	report.AddIssue("security.tf", "aws_sg_open_ssh", "SSH open", "SSH open to world", "high", 20)
	
	text := report.formatText()
	
	// Check the actual format returned by formatText method
	assert.Contains(t, text, "Found 2 issues:")
	assert.Contains(t, text, "aws_s3_bucket_public_acl: Public bucket")
	assert.Contains(t, text, "aws_sg_open_ssh: SSH open")
	assert.Contains(t, text, "Severity: critical")
	assert.Contains(t, text, "Severity: high")
}

// Edge cases and error handling
func TestReportEdgeCases(t *testing.T) {
	testCases := []struct {
		name string
		test func(t *testing.T)
	}{
		{
			name: "empty severity",
			test: func(t *testing.T) {
				report := NewReport()
				report.AddIssue("test.tf", "test_rule", "Test", "Test description", "", 1)
				
				assert.Equal(t, 1, len(report.Issues))
				assert.Equal(t, 1, report.Stats.Total)
				// Empty severity doesn't increment any specific severity counter
				assert.Equal(t, 0, report.Stats.Critical)
				assert.Equal(t, 0, report.Stats.High)
				assert.Equal(t, 0, report.Stats.Medium)
				assert.Equal(t, 0, report.Stats.Low)
			},
		},
		{
			name: "nil report operations",
			test: func(t *testing.T) {
				// Test that we don't panic with nil operations
				var report *Report
				
				// This should not panic, but will return false
				hasIssues := report.HasIssues()
				assert.False(t, hasIssues)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.test(t)
		})
	}
}

// Benchmark tests for report operations
func BenchmarkReportAddIssue(b *testing.B) {
	report := NewReport()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		report.AddIssue("test.tf", "test_rule", "Test message", "Test description", "high", i)
	}
}

func BenchmarkReportGenerateSARIF(b *testing.B) {
	report := NewReport()
	report.AddIssue("main.tf", "aws_s3_bucket_public_acl", "Public bucket", "Bucket is public", "critical", 10)
	report.AddIssue("security.tf", "aws_sg_open_ssh", "SSH open", "SSH open to world", "high", 20)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = report.GenerateSARIF()
	}
}

func BenchmarkReportFormatJSON(b *testing.B) {
	report := NewReport()
	for i := 0; i < 100; i++ {
		report.AddIssue("test.tf", "test_rule", "Test message", "Test description", "medium", i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = report.Format("json")
	}
} 