package types

// Issue represents a security issue found by a rule
type Issue struct {
	Rule        string
	Message     string
	Description string
	Severity    string
	Line        int
} 