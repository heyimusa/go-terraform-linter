package rules

import (
	"github.com/heyimusa/go-terraform-linter/internal/parser"
	"github.com/heyimusa/go-terraform-linter/internal/types"
)

// Rule interface that all security rules must implement
type Rule interface {
	Check(config *parser.Config) []types.Issue
	GetName() string
} 