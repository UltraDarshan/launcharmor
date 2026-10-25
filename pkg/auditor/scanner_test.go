package auditor

import (
	"os"
	"path/filepath"
	"strings"
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

func TestScannerEdgeCases(t *testing.T) {
	if _, err := NewScanner(nil).ScanDirectory("/does/not/exist"); err == nil {
		t.Error("expected error for missing target dir, got nil")
	}

	dir := t.TempDir()
	content := strings.Repeat("x", 70000) + "\n" + // longer than bufio's 64KB default
		`const a = "sk_live_1234567890abcdef12345678";` + "\n" +
		`const b = "sk_live_1234567890abcdef12345678"; // vibeshield:ignore` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "bundle.js"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	report, err := NewScanner(nil).ScanDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 1 || report.Findings[0].Line != 2 {
		t.Errorf("expected exactly 1 finding on line 2, got %+v", report.Findings)
	}
}

func TestRulesMatchRealWorldForms(t *testing.T) {
	cases := map[string]string{
		"VS-001": `apiKey: "sk-proj-Ab3_dEf-GhIjKlMnOpQrStUvWx"`, // modern project keys contain - and _
		"VS-005": `res.setHeader("Access-Control-Allow-Origin", "*");`,
	}
	for _, r := range BuiltinRules() {
		if line, ok := cases[r.ID]; ok && !r.Pattern.MatchString(line) {
			t.Errorf("%s did not match %s", r.ID, line)
		}
	}
}
