package auditor

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// Scanner inspects directory files against security rules.
type Scanner struct {
	rules []Rule
}

func NewScanner(rules []Rule) *Scanner {
	if len(rules) == 0 {
		rules = BuiltinRules()
	}
	return &Scanner{rules: rules}
}

// Ignored directories to avoid scanning huge dependency folders
var ignoredDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
	".next":        true,
	"dist":         true,
	"build":        true,
	"venv":         true,
	".venv":        true,
}

// Scannable extensions
var codeExtensions = map[string]bool{
	".js":   true,
	".ts":   true,
	".jsx":  true,
	".tsx":  true,
	".py":   true,
	".php":  true,
	".go":   true,
	".env":  true,
	".json": true,
	".sql":  true,
	".html": true,
	".sh":   true,
}

func (s *Scanner) ScanDirectory(root string) (*Report, error) {
	report := &Report{
		TargetDir: root,
		Score:     100,
	}

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() {
			if ignoredDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		report.TotalFiles++

		ext := strings.ToLower(filepath.Ext(path))
		base := filepath.Base(path)
		if !codeExtensions[ext] && !strings.HasPrefix(base, ".env") {
			return nil
		}

		// Skip internal rule definitions and binary files
		if strings.Contains(path, "pkg/auditor/rules.go") {
			return nil
		}

		report.ScannedFiles++
		findings, scanErr := s.scanFile(path)
		if scanErr == nil && len(findings) > 0 {
			report.Findings = append(report.Findings, findings...)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	// Calculate Score: deduct based on severity
	score := 100
	for _, f := range report.Findings {
		switch f.Severity {
		case SeverityCritical:
			score -= 30
		case SeverityHigh:
			score -= 15
		case SeverityMedium:
			score -= 8
		case SeverityLow:
			score -= 3
		}
	}
	if score < 0 {
		score = 0
	}
	report.Score = score

	return report, nil
}

func (s *Scanner) scanFile(filePath string) ([]Finding, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var findings []Finding
	scanner := bufio.NewScanner(file)
	lineNum := 0

	// Special check: committing actual .env files
	baseName := filepath.Base(filePath)
	if baseName == ".env" || strings.HasPrefix(baseName, ".env.local") || strings.HasPrefix(baseName, ".env.production") {
		findings = append(findings, Finding{
			RuleID:       "VS-000",
			Title:        "Unsecured Environment File (.env)",
			Severity:     SeverityHigh,
			File:         filePath,
			Line:         1,
			Description:  "Production secrets file is stored directly inside the repository.",
			Solution:     "Add .env to your .gitignore immediately and use secret managers in production.",
			MatchSnippet: baseName,
		})
	}

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Skip excessively long minified files
		if len(line) > 1000 {
			continue
		}

		for _, rule := range s.rules {
			if rule.Pattern.MatchString(line) {
				snippet := strings.TrimSpace(line)
				if len(snippet) > 80 {
					snippet = snippet[:80] + "..."
				}
				findings = append(findings, Finding{
					RuleID:       rule.ID,
					Title:        rule.Title,
					Severity:     rule.Severity,
					File:         filePath,
					Line:         lineNum,
					Description:  rule.Description,
					Solution:     rule.Solution,
					MatchSnippet: snippet,
				})
			}
		}
	}

	return findings, nil
}
