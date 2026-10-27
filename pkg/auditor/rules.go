package auditor

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
)

// Rule represents a detection pattern for vibe-coding vulnerabilities.
type Rule struct {
	ID          string
	Title       string
	Severity    Severity
	Pattern     *regexp.Regexp
	FileFilter  *regexp.Regexp    // if nil, applies to all scanned code files; matched against the base name
	Validate    func(string) bool // optional second check on the matched text; false drops the match
	Secret      bool              // match is a credential: masked in output, still checked on minified lines
	HideRest    bool              // match names a secret: never show what follows it on the line
	Description string
	Solution    string
}

// BuiltinRules returns standard high-risk vulnerability patterns.
func BuiltinRules() []Rule {
	return []Rule{
		{
			ID:       "VS-001",
			Title:    "Hardcoded OpenAI API Key",
			Severity: SeverityCritical,
			Pattern:  regexp.MustCompile(`sk-(?:proj-|svcacct-|admin-)?[a-zA-Z0-9_-]{20,}`),
			// Real keys mix digits and capitals; this rejects CSS classes like sk-folding-cube-...
			Validate: func(m string) bool {
				return !strings.HasPrefix(m, "sk-ant-") && realSecret(m) && strings.ContainsAny(m, "0123456789") && m != strings.ToLower(m)
			},
			Secret:      true,
			Description: "An OpenAI secret key is hardcoded directly in source code.",
			Solution:    "Revoke the key at platform.openai.com, then load a new one from a server-side environment variable.",
		},
		{
			ID:          "VS-002",
			Title:       "Hardcoded Stripe Live Secret Key",
			Severity:    SeverityCritical,
			Pattern:     regexp.MustCompile(`\b[sr]k_live_[0-9a-zA-Z]{24,}`),
			Validate:    realSecret,
			Secret:      true,
			Description: "A live Stripe secret or restricted key is hardcoded in source code. Anyone with it can issue refunds and read customer data.",
			Solution:    "Roll the key in the Stripe dashboard and keep it only in private server environment variables.",
		},
		{
			ID:          "VS-003",
			Title:       "Exposed Supabase Service Role Key",
			Severity:    SeverityCritical,
			Pattern:     regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
			Validate:    isServiceRoleJWT,
			Secret:      true,
			Description: "This JWT carries role=service_role, which bypasses all Row Level Security on your Supabase database.",
			Solution:    "Reset the service_role key in Supabase (Settings > API), use it only in server code, and ship the anon key to clients.",
		},
		{
			ID:          "VS-004",
			Title:       "Dangerous Dynamic Evaluation / Command Execution",
			Severity:    SeverityHigh,
			Pattern:     regexp.MustCompile(`(\beval\s*\(|exec\s*\(\s*\$_(GET|POST|REQUEST)|shell_exec\s*\()`),
			Description: "Code uses dynamic execution with unsanitized parameters, risking Remote Code Execution (RCE).",
			Solution:    "Remove dynamic eval() or shell execution. Use parameterized functions instead.", // launcharmor:ignore
		},
		{
			ID:          "VS-005",
			Title:       "Wildcard Insecure CORS (Access-Control-Allow-Origin: *)",
			Severity:    SeverityMedium,
			Pattern:     regexp.MustCompile(`Access-Control-Allow-Origin['"]?\s*[:=,]\s*['"]\*['"]`),
			Description: "Wildcard CORS allows any malicious website to issue cross-origin requests to your API.",
			Solution:    "Restrict allowed origins to your production and development domains.",
		},
		{
			ID:          "VS-006",
			Title:       "Hardcoded Anthropic API Key",
			Severity:    SeverityCritical,
			Pattern:     regexp.MustCompile(`sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}`),
			Validate:    realSecret,
			Secret:      true,
			Description: "An Anthropic API key is hardcoded in source code. Leaked keys are used to run up large bills within hours.",
			Solution:    "Revoke the key in the Anthropic Console and load a new one from a server-side environment variable.",
		},
		{
			ID:          "VS-007",
			Title:       "Hardcoded AWS Access Key",
			Severity:    SeverityCritical,
			Pattern:     regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`),
			Validate:    realSecret,
			Secret:      true,
			Description: "An AWS access key ID is committed. Paired with its secret it gives access to your AWS account.",
			Solution:    "Deactivate the key in IAM, check CloudTrail for misuse, and use IAM roles or environment variables instead.",
		},
		{
			ID:          "VS-008",
			Title:       "Google API Key in Code",
			Severity:    SeverityMedium,
			Pattern:     regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`),
			Validate:    realSecret,
			Secret:      true,
			Description: "A Google API key is in the code. Firebase web keys are meant to be public, but a Gemini or Maps key here can be abused.",
			Solution:    "If this is a Gemini/Maps key, move it server-side. Either way, add API and HTTP-referrer restrictions in Google Cloud Console.",
		},
		{
			ID:          "VS-009",
			Title:       "Hardcoded GitHub Token",
			Severity:    SeverityCritical,
			Pattern:     regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b`),
			Validate:    realSecret,
			Secret:      true,
			Description: "A GitHub token is committed. It can read or push to your repositories.",
			Solution:    "Revoke it at github.com/settings/tokens and use GitHub Actions secrets instead.",
		},
		{
			ID:          "VS-010",
			Title:       "Private Key Committed",
			Severity:    SeverityCritical,
			Pattern:     regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY( BLOCK)?-----`),
			Description: "A private key is stored in the repository.",
			Solution:    "Remove it, rotate the key pair, and load keys from a secret manager or a file outside the repo.",
		},
		{
			ID:          "VS-011",
			Title:       "Database URL with Embedded Password",
			Severity:    SeverityHigh,
			Pattern:     regexp.MustCompile(`\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?)://[^:\s/"'@]+:[^@\s"']+@[^\s"'/:]+`),
			Validate:    isRemoteDBURL,
			Secret:      true,
			Description: "A database connection string with a real password points at a remote host.",
			Solution:    "Change the database password and read the URL from an environment variable (DATABASE_URL).",
		},
		{
			ID:          "VS-012",
			Title:       "Secret Exposed to the Browser via Public Env Var",
			Severity:    SeverityCritical,
			HideRest:    true,
			Pattern:     regexp.MustCompile(`\b(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC|PUBLIC)_[A-Z0-9_]*(?:SECRET|SERVICE_ROLE|PRIVATE|PASSWORD|OPENAI|ANTHROPIC|GROQ|MISTRAL|REPLICATE|DEEPSEEK|GEMINI)[A-Z0-9_]*\b`),
			Description: "Variables with this prefix are bundled into client JavaScript, so every visitor can read this secret.",
			Solution:    "Drop the public prefix, read the value only in server code (API route / server action / edge function), and rotate the secret.",
		},
		{
			ID:          "VS-013",
			Title:       "Hardcoded Slack Token",
			Severity:    SeverityHigh,
			Pattern:     regexp.MustCompile(`\bxox[abprs]-[0-9]{6,}-[A-Za-z0-9-]{10,}`),
			Validate:    realSecret,
			Secret:      true,
			Description: "A Slack token is committed and can read or post messages in your workspace.",
			Solution:    "Revoke it in the Slack app settings and load a new one from an environment variable.",
		},
		{
			ID:          "VS-014",
			Title:       "Hardcoded Resend API Key",
			Severity:    SeverityCritical,
			Pattern:     regexp.MustCompile(`\bre_[A-Za-z0-9]{20,}\b`),
			Validate:    realSecret,
			Secret:      true,
			Description: "A Resend API key is hardcoded. Anyone with this key can send spoofed transactional emails from your domain.",
			Solution:    "Revoke the key on resend.com/api-keys and store it exclusively in server environment variables.",
		},
		{
			ID:          "VS-015",
			Title:       "Hardcoded Groq API Key",
			Severity:    SeverityCritical,
			Pattern:     regexp.MustCompile(`\bgsk_[A-Za-z0-9]{40,}\b`),
			Validate:    realSecret,
			Secret:      true,
			Description: "A Groq API key is committed. Leaked keys allow attackers to consume your high-throughput AI quota.",
			Solution:    "Rotate the key in Groq Console and move it to a private environment variable.",
		},
		{
			ID:          "VS-016",
			Title:       "Hardcoded PostHog API Key",
			Severity:    SeverityHigh,
			Pattern:     regexp.MustCompile(`\bph[sc]_[A-Za-z0-9_-]{32,}\b`),
			Validate:    realSecret,
			Secret:      true,
			Description: "A PostHog secret or project API key is committed directly into the codebase.",
			Solution:    "Rotate the key in PostHog Project Settings and access it through server-side environment variables.",
		},
		{
			ID:          "VS-017",
			Title:       "Hardcoded Perplexity API Key",
			Severity:    SeverityCritical,
			Pattern:     regexp.MustCompile(`\bpplx-[a-zA-Z0-9]{48}\b`),
			Validate:    realSecret,
			Secret:      true,
			Description: "A Perplexity AI API key is hardcoded in source code.",
			Solution:    "Revoke the key on perplexity.ai/settings/api and load it from a server environment variable.",
		},
		{
			ID:          "VS-018",
			Title:       "Hardcoded Hugging Face Token",
			Severity:    SeverityHigh,
			Pattern:     regexp.MustCompile(`\bhf_[a-zA-Z0-9]{34,}\b`),
			Validate:    realSecret,
			Secret:      true,
			Description: "A Hugging Face user access token is committed into the repository.",
			Solution:    "Revoke the token on huggingface.co/settings/tokens and store it in an environment variable.",
		},
		{
			ID:          "VS-020",
			Title:       "Firebase Rules Allow Public Access",
			Severity:    SeverityCritical,
			Pattern:     regexp.MustCompile(`allow\s+[a-z, ]+:\s*if\s+true\s*;|"\.(?:read|write)"\s*:\s*(?:true|"true")`),
			FileFilter:  regexp.MustCompile(`^(?:firestore|storage|database)\.rules(?:\.json)?$|^database\.rules\.json$`),
			Description: "These Firebase security rules let anyone on the internet read or write your data without logging in.",
			Solution:    "Require auth, e.g. `allow read, write: if request.auth != null && request.auth.uid == userId;`, and test with the Rules Playground.",
		},
	}
}

var placeholderWords = []string{"xxxx", "your", "example", "placeholder", "dummy", "fake", "sample", "replace", "changeme", "redacted", "<", "..."}

func hasPlaceholder(m string) bool {
	lower := strings.ToLower(m)
	for _, w := range placeholderWords {
		if strings.Contains(lower, w) {
			return true
		}
	}
	return false
}

// realSecret drops obvious placeholders and low-variety strings like sk-aaaaaaaa.
func realSecret(m string) bool {
	if hasPlaceholder(m) {
		return false
	}
	distinct := map[rune]bool{}
	for _, r := range m {
		distinct[r] = true
	}
	return len(distinct) >= 10
}

// isServiceRoleJWT decodes the JWT payload; only service_role tokens are secret (anon keys are public by design).
func isServiceRoleJWT(m string) bool {
	parts := strings.Split(m, ".")
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return false
	}
	var claims struct {
		Role string `json:"role"`
	}
	return json.Unmarshal(payload, &claims) == nil && claims.Role == "service_role"
}

var localHostRe = regexp.MustCompile(`@(?:localhost|127\.0\.0\.1|0\.0\.0\.0|db|postgres|mysql|mongo|redis|host\.docker\.internal)$`)

// isRemoteDBURL ignores local/docker-compose dev databases and placeholder passwords.
func isRemoteDBURL(m string) bool {
	if localHostRe.MatchString(m) {
		return false
	}
	pass := m[strings.LastIndex(m[:strings.LastIndex(m, "@")], ":")+1 : strings.LastIndex(m, "@")]
	switch strings.ToLower(pass) {
	case "password", "pass", "secret", "postgres", "root", "admin", "changeme":
		return false
	}
	return len(pass) >= 6 && !hasPlaceholder(pass) && !strings.ContainsAny(pass, "${}*")
}
