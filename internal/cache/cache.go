package cache

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CacheEntry represents a cached file entry
type CacheEntry struct {
	FileHash    string    `json:"file_hash"`
	LastModified time.Time `json:"last_modified"`
	FileSize    int64     `json:"file_size"`
	ScanTime    time.Time `json:"scan_time"`
	Issues      []CachedIssue `json:"issues,omitempty"`
}

// CachedIssue represents a cached security issue
type CachedIssue struct {
	Rule        string `json:"rule"`
	Message     string `json:"message"`
	Severity    string `json:"severity"`
	Line        int    `json:"line"`
	Description string `json:"description"`
}

// Cache manages file caching for performance optimization
type Cache struct {
	cacheDir string
	entries  map[string]*CacheEntry
	enabled  bool
	mutex    sync.RWMutex
}

// NewCache creates a new cache instance
func NewCache(cacheDir string, enabled bool) *Cache {
	if cacheDir == "" {
		cacheDir = ".tflint-cache"
	}
	
	cache := &Cache{
		cacheDir: cacheDir,
		entries:  make(map[string]*CacheEntry),
		enabled:  enabled,
	}
	
	// Load existing cache entries
	cache.loadCache()
	
	return cache
}

// IsFileChanged checks if a file has changed since last scan
func (c *Cache) IsFileChanged(filePath string) (bool, error) {
	if !c.enabled {
		return true, nil // Always consider changed if cache disabled
	}
	
	// Get file info
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return true, err // Consider changed if we can't stat the file
	}
	
	// Calculate file hash
	fileHash, err := c.calculateFileHash(filePath)
	if err != nil {
		return true, err
	}
	
	// Check if we have a cached entry
	cacheKey := c.getCacheKey(filePath)
	c.mutex.RLock()
	cachedEntry, exists := c.entries[cacheKey]
	c.mutex.RUnlock()
	
	if !exists {
		return true, nil // File not in cache, consider changed
	}
	
	// Check if file has changed
	if cachedEntry.FileHash != fileHash ||
		cachedEntry.LastModified != fileInfo.ModTime() ||
		cachedEntry.FileSize != fileInfo.Size() {
		return true, nil
	}
	
	return false, nil
}

// StoreFileResult stores scan results for a file
func (c *Cache) StoreFileResult(filePath string, issues []CachedIssue) error {
	if !c.enabled {
		return nil
	}
	
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return err
	}
	
	fileHash, err := c.calculateFileHash(filePath)
	if err != nil {
		return err
	}
	
	cacheKey := c.getCacheKey(filePath)
	c.mutex.Lock()
	c.entries[cacheKey] = &CacheEntry{
		FileHash:     fileHash,
		LastModified: fileInfo.ModTime(),
		FileSize:     fileInfo.Size(),
		ScanTime:     time.Now(),
		Issues:       issues,
	}
	c.mutex.Unlock()
	
	return c.saveCache()
}

// GetCachedIssues retrieves cached issues for a file
func (c *Cache) GetCachedIssues(filePath string) ([]CachedIssue, bool) {
	if !c.enabled {
		return nil, false
	}
	
	cacheKey := c.getCacheKey(filePath)
	c.mutex.RLock()
	entry, exists := c.entries[cacheKey]
	c.mutex.RUnlock()
	if !exists {
		return nil, false
	}
	
	return entry.Issues, true
}

// ClearCache clears all cached entries
func (c *Cache) ClearCache() error {
	c.mutex.Lock()
	c.entries = make(map[string]*CacheEntry)
	c.mutex.Unlock()
	return c.saveCache()
}

// GetCacheStats returns cache statistics
func (c *Cache) GetCacheStats() map[string]interface{} {
	c.mutex.RLock()
	totalEntries := len(c.entries)
	var totalIssues int
	var oldestScan time.Time
	var newestScan time.Time
	
	for _, entry := range c.entries {
		totalIssues += len(entry.Issues)
		if oldestScan.IsZero() || entry.ScanTime.Before(oldestScan) {
			oldestScan = entry.ScanTime
		}
		if newestScan.IsZero() || entry.ScanTime.After(newestScan) {
			newestScan = entry.ScanTime
		}
	}
	c.mutex.RUnlock()
	
	return map[string]interface{}{
		"total_entries": totalEntries,
		"total_issues":  totalIssues,
		"oldest_scan":   oldestScan,
		"newest_scan":   newestScan,
		"enabled":       c.enabled,
		"cache_dir":     c.cacheDir,
	}
}

// calculateFileHash calculates SHA256 hash of file content
func (c *Cache) calculateFileHash(filePath string) (string, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	
	hash := sha256.Sum256(content)
	return fmt.Sprintf("%x", hash), nil
}

// getCacheKey generates a cache key for a file
func (c *Cache) getCacheKey(filePath string) string {
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return filePath
	}
	return absPath
}

// saveCache saves cache entries to disk
func (c *Cache) saveCache() error {
	if !c.enabled {
		return nil
	}
	
	// Ensure cache directory exists
	if err := os.MkdirAll(c.cacheDir, 0755); err != nil {
		return err
	}
	
	// Clean up any nil entries or invalid data before marshaling
	c.mutex.RLock()
	cleanEntries := make(map[string]*CacheEntry)
	for key, entry := range c.entries {
		if entry != nil && key != "" {
			// Ensure all fields are valid
			cleanEntry := &CacheEntry{
				FileHash:     entry.FileHash,
				LastModified: entry.LastModified,
				FileSize:     entry.FileSize,
				ScanTime:     entry.ScanTime,
				Issues:       make([]CachedIssue, 0, len(entry.Issues)),
			}
			
			// Clean up issues array
			for _, issue := range entry.Issues {
				if issue.Rule != "" && issue.Message != "" {
					cleanEntry.Issues = append(cleanEntry.Issues, issue)
				}
			}
			
			cleanEntries[key] = cleanEntry
		}
	}
	c.mutex.RUnlock()
	
	cacheFile := filepath.Join(c.cacheDir, "cache.json")
	data, err := json.MarshalIndent(cleanEntries, "", "  ")
	if err != nil {
		return err
	}
	
	return os.WriteFile(cacheFile, data, 0644)
}

// loadCache loads cache entries from disk
func (c *Cache) loadCache() error {
	if !c.enabled {
		return nil
	}
	
	cacheFile := filepath.Join(c.cacheDir, "cache.json")
	data, err := os.ReadFile(cacheFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Cache file doesn't exist yet
		}
		return err
	}
	
	c.mutex.Lock()
	err = json.Unmarshal(data, &c.entries)
	c.mutex.Unlock()
	return err
}

// CleanupExpiredEntries removes cache entries older than maxAge
func (c *Cache) CleanupExpiredEntries(maxAge time.Duration) error {
	if !c.enabled {
		return nil
	}
	
	cutoff := time.Now().Add(-maxAge)
	var expiredKeys []string
	
	c.mutex.RLock()
	for key, entry := range c.entries {
		if entry.ScanTime.Before(cutoff) {
			expiredKeys = append(expiredKeys, key)
		}
	}
	c.mutex.RUnlock()
	
	if len(expiredKeys) > 0 {
		c.mutex.Lock()
		for _, key := range expiredKeys {
			delete(c.entries, key)
		}
		c.mutex.Unlock()
		return c.saveCache()
	}
	
	return nil
} 