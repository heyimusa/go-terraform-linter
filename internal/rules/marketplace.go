package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// MarketplaceConfig represents marketplace configuration
type MarketplaceConfig struct {
	Repositories []Repository `json:"repositories" yaml:"repositories"`
	CacheDir     string       `json:"cache_dir" yaml:"cache_dir"`
	Timeout      time.Duration `json:"timeout" yaml:"timeout"`
	AutoUpdate   bool         `json:"auto_update" yaml:"auto_update"`
}

// Repository represents a rule repository
type Repository struct {
	Name        string            `json:"name" yaml:"name"`
	URL         string            `json:"url" yaml:"url"`
	Type        string            `json:"type" yaml:"type"` // "git", "http", "local"
	Branch      string            `json:"branch" yaml:"branch"`
	Path        string            `json:"path" yaml:"path"`
	Credentials map[string]string `json:"credentials" yaml:"credentials"`
	Enabled     bool              `json:"enabled" yaml:"enabled"`
}

// RulePackage represents a package of rules
type RulePackage struct {
	Name         string            `json:"name" yaml:"name"`
	Version      string            `json:"version" yaml:"version"`
	Description  string            `json:"description" yaml:"description"`
	Author       string            `json:"author" yaml:"author"`
	License      string            `json:"license" yaml:"license"`
	Homepage     string            `json:"homepage" yaml:"homepage"`
	Repository   string            `json:"repository" yaml:"repository"`
	Keywords     []string          `json:"keywords" yaml:"keywords"`
	Provider     string            `json:"provider" yaml:"provider"`
	Category     string            `json:"category" yaml:"category"`
	Rules        []RuleDefinition  `json:"rules" yaml:"rules"`
	Dependencies []string          `json:"dependencies" yaml:"dependencies"`
	Metadata     map[string]string `json:"metadata" yaml:"metadata"`
	InstallDate  time.Time         `json:"install_date" yaml:"install_date"`
	UpdateDate   time.Time         `json:"update_date" yaml:"update_date"`
}

// RuleMarketplace manages rule packages and repositories
type RuleMarketplace struct {
	config    MarketplaceConfig
	registry  *DefaultRuleRegistry
	packages  map[string]*RulePackage
	client    *http.Client
	cacheDir  string
}

// NewRuleMarketplace creates a new rule marketplace
func NewRuleMarketplace(config MarketplaceConfig, registry *DefaultRuleRegistry) *RuleMarketplace {
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	
	if config.CacheDir == "" {
		config.CacheDir = filepath.Join(os.TempDir(), "go-terraform-linter", "rules")
	}

	return &RuleMarketplace{
		config:   config,
		registry: registry,
		packages: make(map[string]*RulePackage),
		client: &http.Client{
			Timeout: config.Timeout,
		},
		cacheDir: config.CacheDir,
	}
}

// SearchRules searches for rules in the marketplace
func (m *RuleMarketplace) SearchRules(query string) ([]*RulePackage, error) {
	var results []*RulePackage

	for _, repo := range m.config.Repositories {
		if !repo.Enabled {
			continue
		}

		packages, err := m.searchInRepository(repo, query)
		if err != nil {
			// Log error but continue with other repositories
			continue
		}

		results = append(results, packages...)
	}

	return results, nil
}

// InstallPackage installs a rule package
func (m *RuleMarketplace) InstallPackage(packageName, version string) error {
	// Find the package in repositories
	var targetPackage *RulePackage
	var sourceRepo Repository

	for _, repo := range m.config.Repositories {
		if !repo.Enabled {
			continue
		}

		pkg, err := m.findPackageInRepository(repo, packageName, version)
		if err != nil {
			continue
		}

		if pkg != nil {
			targetPackage = pkg
			sourceRepo = repo
			break
		}
	}

	if targetPackage == nil {
		return fmt.Errorf("package '%s' version '%s' not found in any repository", packageName, version)
	}

	// Download and install the package
	if err := m.downloadPackage(sourceRepo, targetPackage); err != nil {
		return fmt.Errorf("failed to download package: %w", err)
	}

	// Register rules from the package
	for _, ruleDef := range targetPackage.Rules {
		dynamicRule := NewDynamicRule()
		if err := dynamicRule.LoadFromDefinition(ruleDef); err != nil {
			return fmt.Errorf("failed to load rule '%s': %w", ruleDef.Name, err)
		}

		if err := m.registry.RegisterRule(dynamicRule); err != nil {
			return fmt.Errorf("failed to register rule '%s': %w", ruleDef.Name, err)
		}
	}

	// Update package metadata
	targetPackage.InstallDate = time.Now()
	m.packages[packageName] = targetPackage

	// Save package info to cache
	if err := m.savePackageInfo(targetPackage); err != nil {
		// Log warning but don't fail
	}

	return nil
}

// UninstallPackage uninstalls a rule package
func (m *RuleMarketplace) UninstallPackage(packageName string) error {
	pkg, exists := m.packages[packageName]
	if !exists {
		return fmt.Errorf("package '%s' is not installed", packageName)
	}

	// Remove rules from registry (this would need registry support for removal)
	// For now, we'll just mark the package as uninstalled
	delete(m.packages, packageName)

	// Remove from cache
	packagePath := filepath.Join(m.cacheDir, "packages", packageName)
	if err := os.RemoveAll(packagePath); err != nil {
		return fmt.Errorf("failed to remove package files: %w", err)
	}

	return nil
}

// UpdatePackage updates an installed package
func (m *RuleMarketplace) UpdatePackage(packageName string) error {
	pkg, exists := m.packages[packageName]
	if !exists {
		return fmt.Errorf("package '%s' is not installed", packageName)
	}

	// Find latest version
	latestPackages, err := m.SearchRules(packageName)
	if err != nil {
		return fmt.Errorf("failed to search for package updates: %w", err)
	}

	var latestPackage *RulePackage
	for _, p := range latestPackages {
		if p.Name == packageName && (latestPackage == nil || m.compareVersions(p.Version, latestPackage.Version) > 0) {
			latestPackage = p
		}
	}

	if latestPackage == nil {
		return fmt.Errorf("no updates found for package '%s'", packageName)
	}

	if pkg.Version == latestPackage.Version {
		return fmt.Errorf("package '%s' is already at the latest version (%s)", packageName, pkg.Version)
	}

	// Uninstall current version and install new version
	if err := m.UninstallPackage(packageName); err != nil {
		return fmt.Errorf("failed to uninstall current version: %w", err)
	}

	if err := m.InstallPackage(packageName, latestPackage.Version); err != nil {
		return fmt.Errorf("failed to install new version: %w", err)
	}

	return nil
}

// ListInstalledPackages lists all installed packages
func (m *RuleMarketplace) ListInstalledPackages() []*RulePackage {
	var packages []*RulePackage
	for _, pkg := range m.packages {
		packages = append(packages, pkg)
	}
	return packages
}

// GetPackageInfo gets information about an installed package
func (m *RuleMarketplace) GetPackageInfo(packageName string) (*RulePackage, error) {
	pkg, exists := m.packages[packageName]
	if !exists {
		return nil, fmt.Errorf("package '%s' is not installed", packageName)
	}
	return pkg, nil
}

// RefreshRepositories refreshes repository metadata
func (m *RuleMarketplace) RefreshRepositories() error {
	for _, repo := range m.config.Repositories {
		if !repo.Enabled {
			continue
		}

		if err := m.refreshRepository(repo); err != nil {
			// Log error but continue with other repositories
			continue
		}
	}
	return nil
}

// Private methods

func (m *RuleMarketplace) searchInRepository(repo Repository, query string) ([]*RulePackage, error) {
	switch repo.Type {
	case "http":
		return m.searchHTTPRepository(repo, query)
	case "git":
		return m.searchGitRepository(repo, query)
	case "local":
		return m.searchLocalRepository(repo, query)
	default:
		return nil, fmt.Errorf("unsupported repository type: %s", repo.Type)
	}
}

func (m *RuleMarketplace) searchHTTPRepository(repo Repository, query string) ([]*RulePackage, error) {
	// Construct search URL
	searchURL := fmt.Sprintf("%s/search?q=%s", strings.TrimRight(repo.URL, "/"), query)
	
	ctx, cancel := context.WithTimeout(context.Background(), m.config.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", searchURL, nil)
	if err != nil {
		return nil, err
	}

	// Add authentication if provided
	if username, exists := repo.Credentials["username"]; exists {
		if password, exists := repo.Credentials["password"]; exists {
			req.SetBasicAuth(username, password)
		}
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error: %d", resp.StatusCode)
	}

	var searchResult struct {
		Packages []*RulePackage `json:"packages"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&searchResult); err != nil {
		return nil, err
	}

	return searchResult.Packages, nil
}

func (m *RuleMarketplace) searchGitRepository(repo Repository, query string) ([]*RulePackage, error) {
	// For git repositories, we would clone/pull and search locally
	// This is a simplified implementation
	repoPath := filepath.Join(m.cacheDir, "repos", repo.Name)
	
	// Check if repo is already cloned
	if _, err := os.Stat(repoPath); os.IsNotExist(err) {
		// Clone the repository (simplified - would use git commands)
		if err := os.MkdirAll(repoPath, 0755); err != nil {
			return nil, err
		}
	}

	// Search for packages in the repository
	return m.searchLocalRepository(Repository{
		Name: repo.Name,
		Type: "local",
		Path: repoPath,
	}, query)
}

func (m *RuleMarketplace) searchLocalRepository(repo Repository, query string) ([]*RulePackage, error) {
	var packages []*RulePackage

	err := filepath.Walk(repo.Path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() || !strings.HasSuffix(info.Name(), ".json") {
			return nil
		}

		// Try to load as package definition
		data, err := ioutil.ReadFile(path)
		if err != nil {
			return nil
		}

		var pkg RulePackage
		if err := json.Unmarshal(data, &pkg); err != nil {
			return nil
		}

		// Simple query matching
		if query == "" || 
		   strings.Contains(strings.ToLower(pkg.Name), strings.ToLower(query)) ||
		   strings.Contains(strings.ToLower(pkg.Description), strings.ToLower(query)) ||
		   m.containsKeyword(pkg.Keywords, query) {
			packages = append(packages, &pkg)
		}

		return nil
	})

	return packages, err
}

func (m *RuleMarketplace) findPackageInRepository(repo Repository, packageName, version string) (*RulePackage, error) {
	packages, err := m.searchInRepository(repo, packageName)
	if err != nil {
		return nil, err
	}

	for _, pkg := range packages {
		if pkg.Name == packageName && (version == "" || pkg.Version == version) {
			return pkg, nil
		}
	}

	return nil, nil
}

func (m *RuleMarketplace) downloadPackage(repo Repository, pkg *RulePackage) error {
	packageDir := filepath.Join(m.cacheDir, "packages", pkg.Name)
	if err := os.MkdirAll(packageDir, 0755); err != nil {
		return err
	}

	// Save package definition
	packageFile := filepath.Join(packageDir, "package.json")
	data, err := json.MarshalIndent(pkg, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(packageFile, data, 0644)
}

func (m *RuleMarketplace) savePackageInfo(pkg *RulePackage) error {
	packageDir := filepath.Join(m.cacheDir, "packages", pkg.Name)
	if err := os.MkdirAll(packageDir, 0755); err != nil {
		return err
	}

	infoFile := filepath.Join(packageDir, "info.json")
	data, err := json.MarshalIndent(pkg, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(infoFile, data, 0644)
}

func (m *RuleMarketplace) refreshRepository(repo Repository) error {
	// Implementation depends on repository type
	switch repo.Type {
	case "git":
		// Pull latest changes
		return m.pullGitRepository(repo)
	case "http":
		// Clear HTTP cache
		return m.clearHTTPCache(repo)
	}
	return nil
}

func (m *RuleMarketplace) pullGitRepository(repo Repository) error {
	// Simplified git pull implementation
	repoPath := filepath.Join(m.cacheDir, "repos", repo.Name)
	// Would execute: git -C repoPath pull origin branch
	return nil
}

func (m *RuleMarketplace) clearHTTPCache(repo Repository) error {
	// Clear any cached HTTP responses for this repository
	return nil
}

func (m *RuleMarketplace) compareVersions(v1, v2 string) int {
	// Simplified version comparison
	// In a real implementation, use semantic versioning
	if v1 == v2 {
		return 0
	}
	if v1 > v2 {
		return 1
	}
	return -1
}

func (m *RuleMarketplace) containsKeyword(keywords []string, query string) bool {
	lowerQuery := strings.ToLower(query)
	for _, keyword := range keywords {
		if strings.Contains(strings.ToLower(keyword), lowerQuery) {
			return true
		}
	}
	return false
}

// LoadInstalledPackages loads previously installed packages from cache
func (m *RuleMarketplace) LoadInstalledPackages() error {
	packagesDir := filepath.Join(m.cacheDir, "packages")
	if _, err := os.Stat(packagesDir); os.IsNotExist(err) {
		return nil // No packages installed
	}

	return filepath.Walk(packagesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() || info.Name() != "info.json" {
			return nil
		}

		data, err := ioutil.ReadFile(path)
		if err != nil {
			return nil
		}

		var pkg RulePackage
		if err := json.Unmarshal(data, &pkg); err != nil {
			return nil
		}

		// Register rules from the package
		for _, ruleDef := range pkg.Rules {
			dynamicRule := NewDynamicRule()
			if err := dynamicRule.LoadFromDefinition(ruleDef); err != nil {
				continue // Skip invalid rules
			}

			m.registry.RegisterRule(dynamicRule)
		}

		m.packages[pkg.Name] = &pkg
		return nil
	})
} 