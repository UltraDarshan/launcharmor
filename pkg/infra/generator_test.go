package infra

import (
	"strings"
	"testing"
)

func TestGeneratedConfigs(t *testing.T) {
	opts := ConfigOptions{AppName: "demo", Domain: "demo.com", Port: 4000}
	checks := map[string][]string{
		GenerateCaddyfile(opts):      {"demo.com {", "reverse_proxy 127.0.0.1:4000", "Strict-Transport-Security"},
		GenerateNginxConfig(opts):    {"zone=demo_limit", "proxy_pass http://127.0.0.1:4000;", "ssl_certificate /etc/letsencrypt/live/demo.com/fullchain.pem;"},
		GenerateSystemdService(opts): {"NoNewPrivileges=true", "ProtectSystem=strict", "WorkingDirectory=/var/www/demo", "CapabilityBoundingSet="},
	}
	for out, wants := range checks {
		if strings.Contains(out, "%!") {
			t.Errorf("format verb mismatch in output:\n%s", out)
		}
		for _, w := range wants {
			if !strings.Contains(out, w) {
				t.Errorf("missing %q in output:\n%s", w, out)
			}
		}
	}
}
