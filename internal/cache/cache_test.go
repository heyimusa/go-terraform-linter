package cache

import (
	"os"
	"testing"
	"time"
)

func TestNewCache(t *testing.T) {
	tests := []struct {
		name        string
		cacheDir    string
		enabled     bool
		expectError bool
	}{
		{
			name:        "valid cache directory",
			cacheDir:    "./test-cache",
			enabled:     true,
			expectError: false,
		},
		{
			name:        "disabled cache",
			cacheDir:    "./test-cache",
			enabled:     false,
			expectError: false,
		},
		{
			name:        "empty cache directory",
			cacheDir:    "",
			enabled:     true,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up before test
			if tt.cacheDir != "" {
				os.RemoveAll(tt.cacheDir)
			}

			cache := NewCache(tt.cacheDir, tt.enabled)

			if cache == nil {
				t.Fatal("Expected cache object, got nil")
			}

			if cache.enabled != tt.enabled {
				t.Errorf("Expected enabled=%v, got %v", tt.enabled, cache.enabled)
			}

			// Clean up after test
			if tt.cacheDir != "" {
				os.RemoveAll(tt.cacheDir)
			}
		})
	}
}

func TestCacheFileOperations(t *testing.T) {
	tempDir := "./test-cache-ops"
	defer os.RemoveAll(tempDir)

	cache := NewCache(tempDir, true)

	// Create a test file
	testFile := "test.tf"
	testContent := `resource "aws_instance" "test" { ami = "ami-12345" }`
	err := os.WriteFile(testFile, []byte(testContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	defer os.Remove(testFile)

	t.Run("IsFileChanged - new file", func(t *testing.T) {
		changed, err := cache.IsFileChanged(testFile)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if !changed {
			t.Error("Expected new file to be marked as changed")
		}
	})

	t.Run("IsFileChanged - unchanged file", func(t *testing.T) {
		// First call should mark as changed (file not in cache)
		changed1, _ := cache.IsFileChanged(testFile)
		if !changed1 {
			t.Error("Expected first call to mark file as changed")
		}

		// Store the file result to cache it
		testIssues := []CachedIssue{{Rule: "TEST", Message: "Test", Severity: "low", Line: 1}}
		err := cache.StoreFileResult(testFile, testIssues)
		if err != nil {
			t.Errorf("Unexpected error storing file: %v", err)
		}

		// Second call should mark as unchanged (file now cached)
		changed2, err := cache.IsFileChanged(testFile)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if changed2 {
			t.Error("Expected unchanged file to not be marked as changed")
		}
	})

	t.Run("IsFileChanged - modified file", func(t *testing.T) {
		// Modify the file
		time.Sleep(time.Millisecond * 10) // Ensure different timestamp
		modifiedContent := `resource "aws_instance" "test" { ami = "ami-54321" }`
		err := os.WriteFile(testFile, []byte(modifiedContent), 0644)
		if err != nil {
			t.Fatalf("Failed to modify test file: %v", err)
		}

		changed, err := cache.IsFileChanged(testFile)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if !changed {
			t.Error("Expected modified file to be marked as changed")
		}
	})
}

func TestCacheIssueStorage(t *testing.T) {
	tempDir := "./test-cache-issues"
	defer os.RemoveAll(tempDir)

	cache := NewCache(tempDir, true)

	// Create the test file first
	testFile := "test.tf"
	testContent := `resource "aws_instance" "test" { ami = "ami-12345" }`
	err := os.WriteFile(testFile, []byte(testContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	defer os.Remove(testFile)

	testIssues := []CachedIssue{
		{
			Rule:        "TEST_RULE_1",
			Message:     "Test message 1",
			Severity:    "high",
			Line:        10,
			Description: "Test description 1",
		},
		{
			Rule:        "TEST_RULE_2",
			Message:     "Test message 2",
			Severity:    "medium",
			Line:        20,
			Description: "Test description 2",
		},
	}

	t.Run("StoreFileResult", func(t *testing.T) {
		err := cache.StoreFileResult(testFile, testIssues)
		if err != nil {
			t.Errorf("Unexpected error storing file result: %v", err)
		}
	})

	t.Run("GetCachedIssues", func(t *testing.T) {
		issues, found := cache.GetCachedIssues(testFile)
		if !found {
			t.Error("Expected to find cached issues")
		}

		if len(issues) != len(testIssues) {
			t.Errorf("Expected %d issues, got %d", len(testIssues), len(issues))
		}

		for i, issue := range issues {
			expected := testIssues[i]
			if issue.Rule != expected.Rule {
				t.Errorf("Issue[%d].Rule: expected %s, got %s", i, expected.Rule, issue.Rule)
			}
			if issue.Message != expected.Message {
				t.Errorf("Issue[%d].Message: expected %s, got %s", i, expected.Message, issue.Message)
			}
			if issue.Severity != expected.Severity {
				t.Errorf("Issue[%d].Severity: expected %s, got %s", i, expected.Severity, issue.Severity)
			}
			if issue.Line != expected.Line {
				t.Errorf("Issue[%d].Line: expected %d, got %d", i, expected.Line, issue.Line)
			}
		}
	})

	t.Run("GetCachedIssues - not found", func(t *testing.T) {
		_, found := cache.GetCachedIssues("nonexistent.tf")
		if found {
			t.Error("Expected not to find cached issues for nonexistent file")
		}
	})
}

func TestCacheDisabled(t *testing.T) {
	cache := NewCache("./test-cache-disabled", false)

	testFile := "test.tf"
	testContent := `resource "aws_instance" "test" { ami = "ami-12345" }`
	err := os.WriteFile(testFile, []byte(testContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	defer os.Remove(testFile)

	t.Run("IsFileChanged - disabled cache", func(t *testing.T) {
		changed, err := cache.IsFileChanged(testFile)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		// With disabled cache, files should always be marked as changed
		if !changed {
			t.Error("Expected disabled cache to always mark files as changed")
		}
	})

	t.Run("StoreFileResult - disabled cache", func(t *testing.T) {
		testIssues := []CachedIssue{
			{Rule: "TEST", Message: "Test", Severity: "low", Line: 1},
		}
		err := cache.StoreFileResult(testFile, testIssues)
		// Should not error even when disabled
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
	})

	t.Run("GetCachedIssues - disabled cache", func(t *testing.T) {
		_, found := cache.GetCachedIssues(testFile)
		// Should not find anything when disabled
		if found {
			t.Error("Expected disabled cache to not return cached issues")
		}
	})
}

func TestCacheErrorHandling(t *testing.T) {
	cache := NewCache("./test-cache-errors", true)

	t.Run("IsFileChanged - nonexistent file", func(t *testing.T) {
		changed, err := cache.IsFileChanged("nonexistent.tf")
		if err == nil {
			t.Error("Expected error for nonexistent file")
		}
		if !changed {
			t.Error("Expected nonexistent file to be marked as changed (error case)")
		}
	})

	t.Run("StoreFileResult - invalid path", func(t *testing.T) {
		// Create cache with read-only directory to simulate permission error
		readOnlyDir := "./readonly-cache"
		os.Mkdir(readOnlyDir, 0444)
		defer os.RemoveAll(readOnlyDir)

		readOnlyCache := NewCache(readOnlyDir, true)
		err := readOnlyCache.StoreFileResult("test.tf", []CachedIssue{})
		// Should handle error gracefully
		if err == nil {
			t.Log("Note: StoreFileResult should handle permission errors gracefully")
		}
	})
}

func TestCacheStatistics(t *testing.T) {
	tempDir := "./test-cache-stats"
	defer os.RemoveAll(tempDir)

	cache := NewCache(tempDir, true)

	// Create test files
	files := []string{"test1.tf", "test2.tf", "test3.tf"}
	for _, file := range files {
		content := `resource "aws_instance" "test" { ami = "ami-12345" }`
		err := os.WriteFile(file, []byte(content), 0644)
		if err != nil {
			t.Fatalf("Failed to create test file %s: %v", file, err)
		}
		defer os.Remove(file)
	}

	// Test cache hits/misses
	t.Run("cache statistics", func(t *testing.T) {
		// First access - should be misses
		for _, file := range files {
			changed, _ := cache.IsFileChanged(file)
			if !changed {
				t.Errorf("Expected first access to %s to be a miss", file)
			}
		}

		// Store files in cache
		testIssues := []CachedIssue{{Rule: "TEST", Message: "Test", Severity: "low", Line: 1}}
		for _, file := range files {
			cache.StoreFileResult(file, testIssues)
		}

		// Second access - should be hits
		for _, file := range files {
			changed, _ := cache.IsFileChanged(file)
			if changed {
				t.Errorf("Expected second access to %s to be a hit", file)
			}
		}
	})
}

// Benchmark tests
func BenchmarkCacheIsFileChanged(b *testing.B) {
	tempDir := "./bench-cache"
	defer os.RemoveAll(tempDir)

	cache := NewCache(tempDir, true)

	// Create test file
	testFile := "bench.tf"
	content := `resource "aws_instance" "test" { ami = "ami-12345" }`
	err := os.WriteFile(testFile, []byte(content), 0644)
	if err != nil {
		b.Fatalf("Failed to create test file: %v", err)
	}
	defer os.Remove(testFile)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = cache.IsFileChanged(testFile)
	}
}

func BenchmarkCacheStoreFileResult(b *testing.B) {
	tempDir := "./bench-cache-store"
	defer os.RemoveAll(tempDir)

	cache := NewCache(tempDir, true)

	testIssues := []CachedIssue{
		{Rule: "TEST", Message: "Test", Severity: "high", Line: 1},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.StoreFileResult("bench.tf", testIssues)
	}
} 