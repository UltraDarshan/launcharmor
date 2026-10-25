package auditor

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// IgnoreMarker suppresses all findings on a line, e.g. `// vibeshield:ignore`.
const IgnoreMarker = "vibeshield:ignore"

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

	// Fail loudly on a bad target: a typo must not pass CI with 100/100.
	if _, err := os.Stat(root); err != nil {
		return nil, err
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

		// Skip Go test fixtures, and local .env files that git already ignores (never committed)
		if strings.HasSuffix(path, "_test.go") || (strings.HasPrefix(base, ".env") && gitIgnored(path)) {
			return nil
		}

		report.ScannedFiles++
		// Keep partial findings even if reading stopped early (unreadable file or >16MB line)
		findings, _ := s.scanFile(path)
		report.Findings = append(report.Findings, findings...)

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
	// Minified bundles can exceed bufio's 64KB default and silently end the scan.
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
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

		// Skip excessively long minified lines and explicitly suppressed lines
		if len(line) > 1000 || strings.Contains(line, IgnoreMarker) {
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

	return findings, scanner.Err()
}

// gitIgnored reports whether git ignores path; false when git or a repo is unavailable.
func gitIgnored(path string) bool {
	// The scanned tree may be hostile: core.fsmonitor in its .git/config would run a command.
	cmd := exec.Command("git", "-c", "core.fsmonitor=false", "-C", filepath.Dir(path), "check-ignore", "-q", filepath.Base(path))
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	return cmd.Run() == nil
}
