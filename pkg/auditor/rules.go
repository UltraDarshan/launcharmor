package auditor

import (
	"regexp"
)

// Rule represents a detection pattern for vibe-coding vulnerabilities.
type Rule struct {
	ID          string
	Title       string
	Severity    Severity
	Pattern     *regexp.Regexp
	FileFilter  *regexp.Regexp // if nil, applies to all scanned code files
	Description string
	Solution    string
}

// BuiltinRules returns standard high-risk vulnerability patterns.
func BuiltinRules() []Rule {
	return []Rule{
		{
			ID:          "VS-001",
			Title:       "Hardcoded OpenAI API Key",
			Severity:    SeverityCritical,
			Pattern:     regexp.MustCompile(`sk-(?:proj-|svcacct-|admin-)?[a-zA-Z0-9_-]{20,}`),
			Description: "An OpenAI secret key is hardcoded directly in source code.",
			Solution:    "Move key to an environment variable and load it at runtime via .env.",
		},
		{
			ID:          "VS-002",
			Title:       "Hardcoded Stripe Secret Key",
			Severity:    SeverityCritical,
			Pattern:     regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`),
			Description: "A live Stripe secret key is hardcoded in source code.",
			Solution:    "Store Stripe secret keys exclusively in private server environment variables.",
		},
		{
			ID:          "VS-003",
			Title:       "Exposed Supabase Service Role Secret Key",
			Severity:    SeverityCritical,
			Pattern:     regexp.MustCompile(`(supabase_service_role_key|SUPABASE_SERVICE_KEY)\s*[:=]\s*["'][^"']+["']`),
			Description: "The Supabase service_role key bypasses all Row Level Security and must never be exposed.",
			Solution:    "Never ship service_role keys to client frontends. Use SUPABASE_ANON_KEY on client apps.",
		},
		{
			ID:          "VS-004",
			Title:       "Dangerous Dynamic Evaluation / Command Execution",
			Severity:    SeverityHigh,
			Pattern:     regexp.MustCompile(`(\beval\s*\(|exec\s*\(\s*\$_(GET|POST|REQUEST)|shell_exec\s*\()`),
			Description: "Code uses dynamic execution with unsanitized parameters, risking Remote Code Execution (RCE).",
			Solution:    "Remove dynamic eval() or shell execution. Use parameterized functions instead.", // vibeshield:ignore
		},
		{
			ID:          "VS-005",
			Title:       "Wildcard Insecure CORS (Access-Control-Allow-Origin: *)",
			Severity:    SeverityMedium,
			Pattern:     regexp.MustCompile(`Access-Control-Allow-Origin['"]?\s*[:=,]\s*['"]\*['"]`),
			Description: "Wildcard CORS allows any malicious website to issue cross-origin requests to your API.",
			Solution:    "Restrict allowed origins to your production and development domains.",
		},
	}
}
