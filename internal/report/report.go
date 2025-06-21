package report

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/fatih/color"
)

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
	sarif := map[string]interface{}{
		"version": "2.1.0",
		"runs": []interface{}{
			map[string]interface{}{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name": "go-terraform-linter",
						"informationUri": "https://github.com/heyimusa/go-terraform-linter",
					},
				},
				"results": []interface{}{},
			},
		},
	}
	results := []interface{}{}
	for _, issue := range r.Issues {
		results = append(results, map[string]interface{}{
			"ruleId": issue.Rule,
			"message": map[string]string{"text": issue.Message + ". Suggestion: " + issue.FixSuggestion},
			"locations": []interface{}{
				map[string]interface{}{
					"physicalLocation": map[string]interface{}{
						"artifactLocation": map[string]string{"uri": issue.File},
						"region": map[string]int{"startLine": issue.Line},
					},
				},
			},
			"level": strings.ToLower(issue.Severity),
		})
	}
	sarif["runs"].([]interface{})[0].(map[string]interface{})["results"] = results
	out, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		fmt.Println("Failed to marshal SARIF report:", err)
		return
	}
	fmt.Println(string(out))
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
		sarif := map[string]interface{}{
			"version": "2.1.0",
			"runs": []interface{}{
				map[string]interface{}{
					"tool": map[string]interface{}{
						"driver": map[string]interface{}{
							"name": "go-terraform-linter",
							"informationUri": "https://github.com/heyimusa/go-terraform-linter",
						},
					},
					"results": []interface{}{},
				},
			},
		}
		results := []interface{}{}
		for _, issue := range r.Issues {
			results = append(results, map[string]interface{}{
				"ruleId": issue.Rule,
				"message": map[string]string{"text": issue.Message + ". Suggestion: " + issue.FixSuggestion},
				"locations": []interface{}{
					map[string]interface{}{
						"physicalLocation": map[string]interface{}{
							"artifactLocation": map[string]string{"uri": issue.File},
							"region": map[string]int{"startLine": issue.Line},
						},
					},
				},
				"level": strings.ToLower(issue.Severity),
			})
		}
		sarif["runs"].([]interface{})[0].(map[string]interface{})["results"] = results
		out, err = json.MarshalIndent(sarif, "", "  ")
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
	default:
		out, err = json.MarshalIndent(r, "", "  ")
	}
	if err != nil {
		return err
	}
	return os.WriteFile(filename, out, 0644)
} 