package report

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/fatih/color"
)

// SARIF represents the Static Analysis Results Interchange Format
type SARIF struct {
	Schema  string    `json:"$schema"`
	Version string    `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool      `json:"tool"`
	Results []SARIFResult  `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name            string      `json:"name"`
	Version         string      `json:"version"`
	InformationUri  string      `json:"informationUri"`
	Rules           []SARIFRule `json:"rules"`
}

type SARIFRule struct {
	ID               string                 `json:"id"`
	Name             string                 `json:"name"`
	ShortDescription SARIFShortDescription  `json:"shortDescription"`
	FullDescription  SARIFFullDescription   `json:"fullDescription"`
	DefaultConfiguration SARIFConfiguration `json:"defaultConfiguration"`
	Properties       SARIFProperties        `json:"properties"`
}

type SARIFShortDescription struct {
	Text string `json:"text"`
}

type SARIFFullDescription struct {
	Text string `json:"text"`
}

type SARIFConfiguration struct {
	Level string `json:"level"`
}

type SARIFProperties struct {
	Tags     []string `json:"tags"`
	Security string   `json:"security-severity,omitempty"`
}

type SARIFResult struct {
	RuleID    string           `json:"ruleId"`
	RuleIndex int              `json:"ruleIndex"`
	Level     string           `json:"level"`
	Message   SARIFMessage     `json:"message"`
	Locations []SARIFLocation  `json:"locations"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type SARIFRegion struct {
	StartLine int `json:"startLine"`
}

type Issue struct {
	File        string `json:"file"`
	Rule        string `json:"rule"`
	Message     string `json:"message"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Line        int    `json:"line"`
	FixSuggestion string `json:"fix_suggestion,omitempty"`
}

type Report struct {
	Issues []Issue `json:"issues"`
	Stats  Stats   `json:"stats"`
}

type Stats struct {
	Total     int `json:"total"`
	Critical  int `json:"critical"`
	High      int `json:"high"`
	Medium    int `json:"medium"`
	Low       int `json:"low"`
	Files     int `json:"files"`
}

func NewReport() *Report {
	return &Report{
		Issues: make([]Issue, 0),
		Stats:  Stats{},
	}
}

func (r *Report) AddIssue(file, rule, message, description, severity string, line int) {
	issue := Issue{
		File:        file,
		Rule:        rule,
		Message:     message,
		Description: description,
		Severity:    severity,
		Line:        line,
	}
	r.addFixSuggestion(&issue)
	r.Issues = append(r.Issues, issue)
	r.updateStats(severity)
}

func (r *Report) AddError(file, rule, message, description, severity string) {
	issue := Issue{
		File:        file,
		Rule:        rule,
		Message:     message,
		Description: description,
		Severity:    severity,
		Line:        0,
	}
	r.addFixSuggestion(&issue)
	r.Issues = append(r.Issues, issue)
	r.updateStats(severity)
}

func (r *Report) updateStats(severity string) {
	r.Stats.Total++
	
	switch strings.ToLower(severity) {
	case "critical":
		r.Stats.Critical++
	case "high":
		r.Stats.High++
	case "medium":
		r.Stats.Medium++
	case "low":
		r.Stats.Low++
	}
}

func (r *Report) HasIssues() bool {
	if r == nil {
		return false
	}
	return len(r.Issues) > 0
}

func (r *Report) PrintSummary() {
	if len(r.Issues) == 0 {
		color.Green("✅ No security issues found!")
		return
	}

	// Sort issues by severity and file
	sort.Slice(r.Issues, func(i, j int) bool {
		severityOrder := map[string]int{
			"critical": 4,
			"high":     3,
			"medium":   2,
			"low":      1,
		}
		
		severityI := severityOrder[strings.ToLower(r.Issues[i].Severity)]
		severityJ := severityOrder[strings.ToLower(r.Issues[j].Severity)]
		
		if severityI != severityJ {
			return severityI > severityJ
		}
		
		return r.Issues[i].File < r.Issues[j].File
	})

	// Print summary
	fmt.Println("\n" + strings.Repeat("=", 80))
	color.Red("🔍 Terraform Security Scan Results")
	fmt.Println(strings.Repeat("=", 80))

	// Print statistics
	fmt.Printf("\n📊 Summary:\n")
	fmt.Printf("   Total Issues: %d\n", r.Stats.Total)
	
	if r.Stats.Critical > 0 {
		color.Red("   Critical: %d", r.Stats.Critical)
	}
	if r.Stats.High > 0 {
		color.Yellow("   High: %d", r.Stats.High)
	}
	if r.Stats.Medium > 0 {
		color.Blue("   Medium: %d", r.Stats.Medium)
	}
	if r.Stats.Low > 0 {
		color.Green("   Low: %d", r.Stats.Low)
	}

	// Group issues by file
	issuesByFile := make(map[string][]Issue)
	for _, issue := range r.Issues {
		issuesByFile[issue.File] = append(issuesByFile[issue.File], issue)
	}

	// Print detailed issues
	fmt.Println("\n🔍 Detailed Issues:")
	fmt.Println(strings.Repeat("-", 80))

	for _, file := range sortedKeys(issuesByFile) {
		issues := issuesByFile[file]
		fmt.Printf("\n📁 File: %s\n", file)
		
		for _, issue := range issues {
			r.printIssue(issue)
		}
	}

	fmt.Println("\n" + strings.Repeat("=", 80))
	
	if r.Stats.Critical > 0 || r.Stats.High > 0 {
		color.Red("❌ Critical and High severity issues found!")
	} else {
		color.Yellow("⚠️  Issues found but no critical/high severity problems")
	}
}

func (r *Report) printIssue(issue Issue) {
	var severityColor *color.Color
	var severityIcon string
	
	switch strings.ToLower(issue.Severity) {
	case "critical":
		severityColor = color.New(color.FgRed, color.Bold)
		severityIcon = "🚨"
	case "high":
		severityColor = color.New(color.FgRed)
		severityIcon = "⚠️"
	case "medium":
		severityColor = color.New(color.FgYellow)
		severityIcon = "⚡"
	case "low":
		severityColor = color.New(color.FgBlue)
		severityIcon = "ℹ️"
	default:
		severityColor = color.New(color.FgWhite)
		severityIcon = "❓"
	}

	lineInfo := ""
	if issue.Line > 0 {
		lineInfo = fmt.Sprintf(" (line %d)", issue.Line)
	}

	fmt.Printf("  %s [%s] %s%s\n", 
		severityIcon, 
		severityColor.Sprint(strings.ToUpper(issue.Severity)), 
		issue.Message,
		lineInfo)
	
	fmt.Printf("     Rule: %s\n", issue.Rule)
	fmt.Printf("     Description: %s\n", issue.Description)
	fmt.Println()
}

func (r *Report) SaveToFile(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(r)
}

func sortedKeys(m map[string][]Issue) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (r *Report) addFixSuggestion(issue *Issue) {
	switch issue.Rule {
	case "MISSING_TAGS":
		issue.FixSuggestion = "Add a 'tags' block with appropriate key-value pairs."
	case "UNENCRYPTED_STORAGE", "ENCRYPTION_COMPLIANCE":
		issue.FixSuggestion = "Set 'encrypted = true' for this resource."
	case "PUBLIC_ACCESS", "OPEN_PORTS":
		issue.FixSuggestion = "Restrict 'cidr_blocks' to trusted IP ranges."
	case "WEAK_PASSWORD":
		issue.FixSuggestion = "Use a password with at least 8 characters, including numbers and symbols."
	case "EXPOSED_SECRETS":
		issue.FixSuggestion = "Store secrets in variables or secret management systems."
	case "DEPRECATED_RESOURCES":
		issue.FixSuggestion = "Use the recommended resource type instead."
	case "COST_OPTIMIZATION":
		issue.FixSuggestion = "Consider using a smaller instance type."
	case "IAM_LEAST_PRIVILEGE":
		issue.FixSuggestion = "Avoid using 'Action: *' and 'Resource: *' in IAM policies."
	case "WEAK_CRYPTO":
		issue.FixSuggestion = "Use TLSv1.2 or higher."
	case "MISSING_BACKUP":
		issue.FixSuggestion = "Set 'backup_retention_period' to a value greater than 0."
	// AWS-specific rules
	case "aws_s3_bucket_public_acl":
		issue.FixSuggestion = "Remove public ACL permissions and use bucket policies instead."
	case "aws_sg_open_ssh":
		issue.FixSuggestion = "Restrict SSH access to specific IP ranges instead of 0.0.0.0/0."
	case "aws_instance_unencrypted":
		issue.FixSuggestion = "Enable EBS encryption by setting 'encrypted = true'."
	case "aws_rds_unencrypted":
		issue.FixSuggestion = "Enable RDS encryption by setting 'storage_encrypted = true'."
	default:
		// Generate a generic fix suggestion based on rule patterns
		if strings.Contains(strings.ToLower(issue.Rule), "public") || strings.Contains(strings.ToLower(issue.Rule), "open") {
			issue.FixSuggestion = "Restrict access to trusted sources only."
		} else if strings.Contains(strings.ToLower(issue.Rule), "encrypt") || strings.Contains(strings.ToLower(issue.Rule), "unencrypted") {
			issue.FixSuggestion = "Enable encryption for this resource."
		} else if strings.Contains(strings.ToLower(issue.Rule), "tag") {
			issue.FixSuggestion = "Add appropriate tags to this resource."
		} else {
			issue.FixSuggestion = "Review and fix this security issue according to best practices."
		}
	}
}

func (r *Report) PrintJSON() {
	out, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		fmt.Println("Failed to marshal JSON report:", err)
		return
	}
	fmt.Println(string(out))
}

func (r *Report) PrintSARIF() {
	data, err := r.GenerateSARIF()
	if err != nil {
		fmt.Println("Failed to generate SARIF report:", err)
		return
	}
	fmt.Println(string(data))
}

func (r *Report) PrintHTML() {
	fmt.Println("<html><head><title>Terraform Linter Report</title></head><body>")
	fmt.Println("<h1>Terraform Linter Report</h1>")
	fmt.Println("<table border='1'><tr><th>File</th><th>Rule</th><th>Message</th><th>Severity</th><th>Line</th><th>Fix Suggestion</th></tr>")
	for _, issue := range r.Issues {
		fmt.Printf("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%d</td><td>%s</td></tr>\n",
			issue.File, issue.Rule, issue.Message, issue.Severity, issue.Line, issue.FixSuggestion)
	}
	fmt.Println("</table></body></html>")
}

func (r *Report) SaveToFileWithFormat(filename, format string) error {
	var out []byte
	var err error
	switch format {
	case "json":
		out, err = json.MarshalIndent(r, "", "  ")
	case "sarif":
		out, err = r.GenerateSARIF()
	case "html":
		html := "<html><head><title>Terraform Linter Report</title></head><body>"
		html += "<h1>Terraform Linter Report</h1>"
		html += "<table border='1'><tr><th>File</th><th>Rule</th><th>Message</th><th>Severity</th><th>Line</th><th>Fix Suggestion</th></tr>"
		for _, issue := range r.Issues {
			html += fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%d</td><td>%s</td></tr>",
				issue.File, issue.Rule, issue.Message, issue.Severity, issue.Line, issue.FixSuggestion)
		}
		html += "</table></body></html>"
		out = []byte(html)
	case "text":
		out = []byte(r.formatText())
	default:
		out, err = json.MarshalIndent(r, "", "  ")
	}
	if err != nil {
		return err
	}
	return os.WriteFile(filename, out, 0644)
}

// formatText returns the text representation of the report
func (r *Report) formatText() string {
	// This would capture the output from PrintSummary but for now return a simple format
	if len(r.Issues) == 0 {
		return "✅ No security issues found!"
	}
	
	result := fmt.Sprintf("Found %d issues:\n", len(r.Issues))
	for _, issue := range r.Issues {
		result += fmt.Sprintf("- %s: %s (Severity: %s, File: %s, Line: %d)\n", 
			issue.Rule, issue.Message, issue.Severity, issue.File, issue.Line)
	}
	return result
}

// GenerateSARIF converts a report to SARIF format
func (r *Report) GenerateSARIF() ([]byte, error) {
	// Create unique rules map
	rulesMap := make(map[string]Issue)
	ruleIndexMap := make(map[string]int)
	
	for _, issue := range r.Issues {
		if _, exists := rulesMap[issue.Rule]; !exists {
			rulesMap[issue.Rule] = issue
			ruleIndexMap[issue.Rule] = len(rulesMap) - 1
		}
	}
	
	// Convert rules to SARIF format
	var sarifRules []SARIFRule
	for ruleID, issue := range rulesMap {
		sarifRule := SARIFRule{
			ID:   ruleID,
			Name: ruleID,
			ShortDescription: SARIFShortDescription{
				Text: issue.Message,
			},
			FullDescription: SARIFFullDescription{
				Text: issue.Description,
			},
			DefaultConfiguration: SARIFConfiguration{
				Level: r.convertSeverityToSARIF(issue.Severity),
			},
			Properties: SARIFProperties{
				Tags: []string{"security", "terraform", r.getCloudProvider(ruleID)},
				Security: r.convertSeverityToSecurityScore(issue.Severity),
			},
		}
		sarifRules = append(sarifRules, sarifRule)
	}
	
	// Convert results to SARIF format
	var sarifResults []SARIFResult
	for _, issue := range r.Issues {
		sarifResult := SARIFResult{
			RuleID:    issue.Rule,
			RuleIndex: ruleIndexMap[issue.Rule],
			Level:     r.convertSeverityToSARIF(issue.Severity),
			Message: SARIFMessage{
				Text: fmt.Sprintf("%s: %s", issue.Message, issue.Description),
			},
			Locations: []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{
							URI: issue.File,
						},
						Region: SARIFRegion{
							StartLine: issue.Line,
						},
					},
				},
			},
		}
		sarifResults = append(sarifResults, sarifResult)
	}
	
	// Create SARIF document
	sarif := SARIF{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           "go-terraform-linter",
						Version:        "2.0.0",
						InformationUri: "https://github.com/heyimusa/go-terraform-linter",
						Rules:          sarifRules,
					},
				},
				Results: sarifResults,
			},
		},
	}
	
	return json.MarshalIndent(sarif, "", "  ")
}

// convertSeverityToSARIF converts custom severity levels to SARIF levels
func (r *Report) convertSeverityToSARIF(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "error"
	case "high":
		return "error"
	case "medium":
		return "warning"
	case "low":
		return "note"
	default:
		return "warning"
	}
}

// convertSeverityToSecurityScore converts severity to security score for SARIF
func (r *Report) convertSeverityToSecurityScore(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "9.0"
	case "high":
		return "7.0"
	case "medium":
		return "5.0"
	case "low":
		return "3.0"
	default:
		return "5.0"
	}
}

// getCloudProvider extracts cloud provider from rule name
func (r *Report) getCloudProvider(ruleID string) string {
	if strings.HasPrefix(ruleID, "AZURE_") {
		return "azure"
	} else if strings.HasPrefix(ruleID, "AWS_") {
		return "aws"
	}
	return "general"
}

// Format generates a report in the specified format
func (r *Report) Format(format string) (string, error) {
	switch strings.ToLower(format) {
	case "json":
		data, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			return "", fmt.Errorf("failed to marshal JSON: %w", err)
		}
		return string(data), nil
	case "sarif":
		data, err := r.GenerateSARIF()
		if err != nil {
			return "", fmt.Errorf("failed to generate SARIF: %w", err)
		}
		return string(data), nil
	case "html":
		html := "<html><head><title>Terraform Linter Report</title></head><body>"
		html += "<h1>Terraform Linter Report</h1>"
		html += "<table border='1'><tr><th>File</th><th>Rule</th><th>Message</th><th>Severity</th><th>Line</th><th>Fix Suggestion</th></tr>"
		for _, issue := range r.Issues {
			html += fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%d</td><td>%s</td></tr>",
				issue.File, issue.Rule, issue.Message, issue.Severity, issue.Line, issue.FixSuggestion)
		}
		html += "</table></body></html>"
		return html, nil
	case "text":
		return r.formatText(), nil
	default:
		return "", fmt.Errorf("unsupported format: %s", format)
	}
} 