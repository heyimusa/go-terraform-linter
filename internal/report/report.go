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