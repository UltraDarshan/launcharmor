package auditor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScannerDetectsSecrets(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "vibeshield-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	testFile := filepath.Join(tempDir, "app.js")
	content := `
const openaiKey = "sk-1234567890abcdef1234567890abcdef";
const stripeKey = "sk_live_1234567890abcdef12345678";
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	scanner := NewScanner(nil)
	report, err := scanner.ScanDirectory(tempDir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(report.Findings) < 2 {
		t.Errorf("Expected at least 2 findings, got %d", len(report.Findings))
	}

	if report.Score >= 100 {
		t.Errorf("Expected score to be deducted, got %d", report.Score)
	}
}
