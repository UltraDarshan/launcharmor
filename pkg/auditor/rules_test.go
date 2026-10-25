package auditor

import (
	"encoding/base64"
	"strings"
	"testing"
)

// Fake credentials are assembled at runtime so this file never looks like a real leak to push protection.
func jwt(role string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." +
		enc([]byte(`{"iss":"supabase","ref":"abcdefghijklmnop","role":"`+role+`","iat":1700000000}`)) + "." +
		"Xk9_sQ2vR7mZp3LwT8yBn4HcJd6FgA1e"
}

func TestRuleAccuracy(t *testing.T) {
	tests := []struct {
		rule string
		line string
		want bool
	}{
		// Leaks that must be caught
		{"VS-001", `const ai = new OpenAI({ apiKey: "sk-` + `proj-Ab3dEf9GhIjK2lMnOpQ7rStUvWx_Yz-1" })`, true},
		{"VS-001", `OPENAI_API_KEY="sk-` + `Q2w3E4r5T6y7U8i9O0pAsDfGhJkL1234567890abcdEF"`, true},
		{"VS-002", `stripe = Stripe("sk_li` + `ve_51HxYz2AbCdEfGh3IjKlMn4OpQr")`, true},
		{"VS-002", `key: "rk_li` + `ve_51HxYz2AbCdEfGh3IjKlMn4OpQr"`, true},
		{"VS-003", `createClient(url, "` + jwt("service_role") + `")`, true},
		{"VS-006", `"sk-` + `ant-api03-` + strings.Repeat("Ab3_Cd9-Ef7G", 8) + `"`, true},
		{"VS-007", `aws_access_key_id = AKIA` + `Z7QW3ERT5YUI8OPL`, true},
		{"VS-009", `token: "ghp_` + `A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"`, true},
		{"VS-010", `-----BEGIN OPENSSH ` + `PRIVATE KEY-----`, true},
		{"VS-011", `DATABASE_URL=postgres://app:Tr0ub4dor3x@db.abcd.supabase.co:5432/postgres`, true},
		{"VS-012", `const key = process.env.NEXT_PUBLIC_OPENAI_API_KEY`, true},
		{"VS-012", `VITE_SUPABASE_SERVICE_ROLE_KEY=abc`, true},
		{"VS-013", `xoxb-` + `123456789012-1234567890123-AbCdEfGhIjKlMnOp`, true},
		{"VS-014", `const resend = "re_` + `1234567890AbCdEfGhIjKl"`, true},
		{"VS-015", `const groq = "gsk_` + `AbCdEf1234567890GhIjKlMnOpQrStUvWxYz01234567"`, true},
		{"VS-016", `const ph = "phc_` + `AbCdEf1234567890GhIjKlMnOpQrStUv"`, true},

		// Look-alikes that must NOT be flagged
		{"VS-001", `<div class="sk-folding-cube-animation-wrapper">`, false}, // SpinKit CSS
		{"VS-001", `OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`, false},
		{"VS-001", `apiKey: "sk-your-openai-api-key-goes-here-now"`, false},
		{"VS-001", `"sk-` + `ant-api03-` + strings.Repeat("Ab3_Cd9-Ef7G", 8) + `"`, false}, // Anthropic, not OpenAI
		{"VS-002", `stripe = Stripe("sk_test_51HxYz2AbCdEfGh3IjKlMn4OpQr")`, false},
		{"VS-003", `createClient(url, "` + jwt("anon") + `")`, false}, // anon key is public by design
		{"VS-011", `DATABASE_URL=postgres://postgres:postgres@localhost:5432/app`, false},
		{"VS-011", `DATABASE_URL=postgres://user:password@db.example.com/app`, false},
		{"VS-011", `url: postgres://app:${DB_PASSWORD}@db.prod.internal/app`, false},
		{"VS-012", `NEXT_PUBLIC_SUPABASE_ANON_KEY=abc`, false},
		{"VS-012", `NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_live_abc`, false},
	}

	rules := map[string]Rule{}
	for _, r := range BuiltinRules() {
		rules[r.ID] = r
	}
	for _, tt := range tests {
		r, ok := rules[tt.rule]
		if !ok {
			t.Fatalf("unknown rule %s", tt.rule)
		}
		if got := firstValidMatch(r, tt.line) != ""; got != tt.want {
			t.Errorf("%s on %q: got %v, want %v", tt.rule, tt.line, got, tt.want)
		}
	}
}

func TestFirebaseRuleOnlyInRulesFiles(t *testing.T) {
	var r Rule
	for _, rule := range BuiltinRules() {
		if rule.ID == "VS-020" {
			r = rule
		}
	}
	line := `      allow read, write: if true;`
	if firstValidMatch(r, line) == "" || !r.FileFilter.MatchString("firestore.rules") {
		t.Error("expected open Firestore rule to be flagged in firestore.rules")
	}
	if r.FileFilter.MatchString("app.js") {
		t.Error("Firebase rule must not apply to app.js")
	}
}

func TestSnippetMasksSecret(t *testing.T) {
	key := "sk_li" + "ve_51HxYz2AbCdEfGh3IjKlMn4OpQr"
	got := snippetAround(`const stripe = Stripe("`+key+`");`, key, Rule{Secret: true})
	if strings.Contains(got, key) || !strings.Contains(got, "sk_live_") {
		t.Errorf("snippet should show a masked prefix only, got %q", got)
	}
}

func TestMaskURLKeepsHost(t *testing.T) {
	if got := Mask("postgres://app:S3cr3tPass99@db.abc.supabase.co"); got != "postgres://app:********@db.abc.supabase.co" {
		t.Errorf("got %q", got)
	}
}

func TestSnippetNeverLeaksNearbySecrets(t *testing.T) {
	key := "sk_li" + "ve_51HxYz2AbCdEfGh3IjKlMn4OpQr"
	cases := []struct{ line, match, secret string }{
		// VS-012 matches the variable name; the assigned value must still be hidden
		{`VITE_SUPABASE_SERVICE_ROLE_KEY=Zq8rT2vX9mP4kL7wN3bY6cH1`, "VITE_SUPABASE_SERVICE_ROLE_KEY", "Zq8rT2vX9mP4kL7wN3bY6cH1"},
		// a second credential elsewhere on the same line
		{`const NEXT_PUBLIC_PAY_SECRET = "` + key + `"`, "NEXT_PUBLIC_PAY_SECRET", key},
		// other assignment syntaxes: JSON, Go :=, env fallback
		{`{"NEXT_PUBLIC_DB_PASSWORD": "Zq8rT2vX9mP4kL7wN3bY6cH1"}`, "NEXT_PUBLIC_DB_PASSWORD", "Zq8rT2vX9mP4kL7wN3bY6cH1"},
		{`VITE_APP_SECRET := "Zq8rT2vX9mP4kL7wN3bY6cH1"`, "VITE_APP_SECRET", "Zq8rT2vX9mP4kL7wN3bY6cH1"},
		{`const k = process.env.NEXT_PUBLIC_OPENAI_KEY || "Zq8rT2vX9mP4kL7wN3bY6cH1"`, "NEXT_PUBLIC_OPENAI_KEY", "Zq8rT2vX9mP4kL7wN3bY6cH1"},
		// value written before the name
		{`const v = "Zq8rT2vX9mP4kL7wN3bY6cH1"; export const NEXT_PUBLIC_APP_SECRET = v`, "NEXT_PUBLIC_APP_SECRET", "Zq8rT2vX9mP4kL7wN3bY6cH1"},
	}
	for _, c := range cases {
		if got := snippetAround(c.line, c.match, Rule{HideRest: true}); strings.Contains(got, c.secret) {
			t.Errorf("snippet leaks %q: %q", c.secret, got)
		}
	}
	if got := Mask("postgres://u:pa:ss99word@db.example.com"); got != "postgres://u:********@db.example.com" {
		t.Errorf("password with ':' partly shown: %q", got)
	}
}

func TestSnippetCutNeverExposesKeyTail(t *testing.T) {
	key := "sk_li" + "ve_51HxYz2AbCdEfGh3IjKlMn4OpQrStUvWxYz"
	// 52 chars precede eval(, so the 40-char window starts right after "sk_live_": cutting before
	// masking would leave a prefix-less tail that no longer looks like a key
	line := `pay(` + key + `);    eval(input)`
	if got := snippetAround(line, "eval(", Rule{}); strings.Contains(got, "IjKlMn4OpQr") {
		t.Errorf("snippet exposes the tail of a key: %q", got)
	}
}

func TestSnippetMatchInsideCredential(t *testing.T) {
	// Only a name-shaped match can sit inside a key. Masking each side of the match separately
	// would see two fragments too short to look like a key, and print them.
	line := `k = "sk-` + `Ab3-NEXT_PUBLIC_X_SECRET-Q9zT7"`
	if got := snippetAround(line, "NEXT_PUBLIC_X_SECRET", Rule{}); strings.Contains(got, "Q9zT7") {
		t.Errorf("snippet exposes the key around the match: %q", got)
	}
}
