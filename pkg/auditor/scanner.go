package auditor

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
	".svelte-kit":  true,
	".nuxt":        true,
	".output":      true,
	".vercel":      true,
	".turbo":       true,
	".expo":        true,
	"coverage":     true,
	"__pycache__":  true,
	"target":       true,
}

// Scannable extensions
var codeExtensions = map[string]bool{
	".js":     true,
	".ts":     true,
	".jsx":    true,
	".tsx":    true,
	".py":     true,
	".php":    true,
	".go":     true,
	".env":    true,
	".json":   true,
	".sql":    true,
	".html":   true,
	".sh":     true,
	".mjs":    true,
	".cjs":    true,
	".vue":    true,
	".svelte": true,
	".astro":  true,
	".yml":    true,
	".yaml":   true,
	".toml":   true,
	".rb":     true,
	".java":   true,
	".kt":     true,
	".dart":   true,
	".swift":  true,
	".rules":  true,
	".pem":    true,
	".key":    true,
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
	if strings.HasPrefix(baseName, ".env") && !envTemplateRe.MatchString(baseName) {
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

		if strings.Contains(line, IgnoreMarker) {
			continue
		}
		// Minified lines: only look for credentials, code-pattern rules are too noisy there
		minified := len(line) > 1000

		for _, rule := range s.rules {
			if (minified && !rule.Secret) || (rule.FileFilter != nil && !rule.FileFilter.MatchString(baseName)) {
				continue
			}
			match := firstValidMatch(rule, line)
			if match == "" {
				continue
			}
			findings = append(findings, Finding{
				RuleID:       rule.ID,
				Title:        rule.Title,
				Severity:     rule.Severity,
				File:         filePath,
				Line:         lineNum,
				Description:  rule.Description,
				Solution:     rule.Solution,
				MatchSnippet: snippetAround(line, match, rule.Secret),
			})
		}
	}

	return findings, scanner.Err()
}

var envTemplateRe = regexp.MustCompile(`\.(?:example|sample|template|dist|defaults?)$`)

func firstValidMatch(rule Rule, line string) string {
	for _, m := range rule.Pattern.FindAllString(line, -1) {
		if rule.Validate == nil || rule.Validate(m) {
			return m
		}
	}
	return ""
}

// assignedValueRe captures the value assigned right after a matched name, e.g. the "value" in NAME="value".
var assignedValueRe = regexp.MustCompile(`^(\s*[:=]\s*["'\x60]?)([^\s"'\x60,;)]+)`)

// snippetAround returns up to ~100 chars of context around match. It masks the match if it is a
// secret, the value assigned to it, and anything else on the line that looks like a credential,
// so findings never re-leak keys into (often public) CI logs.
func snippetAround(line, match string, secret bool) string {
	i := strings.Index(line, match)
	rest := line[i+len(match):]
	shown := match
	if secret {
		shown = Mask(match)
	} else if m := assignedValueRe.FindStringSubmatch(rest); m != nil && !strings.HasPrefix(m[2], "process.env") {
		rest = m[1] + Mask(m[2]) + rest[len(m[0]):]
	}
	start := max(0, i-40)
	masked := maskSecrets(line[start:i]) + shown + maskSecrets(rest)
	end := min(len(masked), len(line[start:i])+len(shown)+40)
	out := strings.TrimSpace(masked[:end])
	if start > 0 {
		out = "..." + out
	}
	if end < len(masked) {
		out += "..."
	}
	return strings.ToValidUTF8(out, "")
}

// maskSecrets masks every credential-shaped string, whether or not it passed a rule's validator.
func maskSecrets(text string) string {
	for _, r := range secretRules {
		text = r.Pattern.ReplaceAllStringFunc(text, Mask)
	}
	return text
}

var secretRules = func() []Rule {
	var out []Rule
	for _, r := range BuiltinRules() {
		if r.Secret {
			out = append(out, r)
		}
	}
	return out
}()

// Mask keeps a short recognizable prefix of a secret and hides the rest.
func Mask(secret string) string {
	// URLs: hide the whole password, even if it contains ':' (postgres://app:****@db.host)
	if scheme := strings.Index(secret, "://"); scheme >= 0 {
		if at := strings.LastIndex(secret, "@"); at > scheme {
			if colon := strings.Index(secret[scheme+3:at], ":"); colon >= 0 {
				return secret[:scheme+3+colon+1] + "********" + secret[at:]
			}
		}
	}
	keep := min(8, len(secret)/4)
	return secret[:keep] + strings.Repeat("*", 8)
}

// gitIgnored reports whether git ignores path; false when git or a repo is unavailable.
func gitIgnored(path string) bool {
	// The scanned tree may be hostile: core.fsmonitor in its .git/config would run a command.
	cmd := exec.Command("git", "-c", "core.fsmonitor=false", "-C", filepath.Dir(path), "check-ignore", "-q", filepath.Base(path))
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	return cmd.Run() == nil
}
