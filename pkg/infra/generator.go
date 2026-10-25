package infra

import (
	"fmt"
	"os"
	"path/filepath"
)

// ConfigOptions defines deployment parameters for generating Linux infrastructure configs.
type ConfigOptions struct {
	AppName     string
	Domain      string
	Port        int
	User        string
	WorkingDir  string
	ExecCommand string
}

// GenerateCaddyfile returns a hardened reverse-proxy configuration for Caddy with automated HTTPS,
// security headers, and compression (core Caddy has no rate limiter; use the Nginx config for that).
func GenerateCaddyfile(opts ConfigOptions) string {
	domain := opts.Domain
	if domain == "" {
		domain = "example.com"
	}
	port := opts.Port
	if port == 0 {
		port = 3000
	}

	return fmt.Sprintf(`# LaunchArmor Production Caddyfile - Hardened Reverse Proxy
# Target: %s -> Local Service :%d

%s {
	# Reverse proxy (Caddy sets X-Forwarded-For/Proto/Host itself)
	reverse_proxy 127.0.0.1:%d {
		header_up X-Real-IP {remote_host}
	}

	# Strict Security Headers
	header {
		# Enforce HTTPS for 1 year including subdomains (add "; preload" only once you commit to hstspreload.org)
		Strict-Transport-Security "max-age=31536000; includeSubDomains"
		# Prevent MIME-type sniffing
		X-Content-Type-Options "nosniff"
		# Disallow embedding in frames/iframes to stop clickjacking
		X-Frame-Options "DENY"
		# Disable the legacy browser XSS auditor (it can introduce leaks; OWASP recommends 0)
		X-XSS-Protection "0"
		# Referrer policy privacy protection
		Referrer-Policy "strict-origin-when-cross-origin"
		# Restrict browser APIs (camera, microphone, geolocation)
		Permissions-Policy "camera=(), microphone=(), geolocation=()"
		# Hide backend server identity
		-Server
	}

	# Enable modern compression (Gzip and Zstandard)
	encode zstd gzip

	# Logging with privacy-focused rotation
	log {
		output file /var/log/caddy/%s.access.log {
			roll_size 10mb
			roll_keep 5
		}
	}
}
`, opts.AppName, port, domain, port, opts.AppName)
}

// GenerateNginxConfig returns a hardened Nginx configuration with rate-limiting zones and secure SSL settings.
func GenerateNginxConfig(opts ConfigOptions) string {
	domain := opts.Domain
	if domain == "" {
		domain = "example.com"
	}
	port := opts.Port
	if port == 0 {
		port = 3000
	}

	return fmt.Sprintf(`# LaunchArmor Hardened Nginx Configuration
# Target: %s

# Rate limiting zone: max 10 requests/second per IP with burst up to 20
limit_req_zone $binary_remote_addr zone=%s_limit:10m rate=10r/s;

server {
    listen 80;
    listen [::]:80;
    server_name %s;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name %s;

    # SSL Certificates: issue first with: sudo certbot certonly --standalone -d %s
    ssl_certificate /etc/letsencrypt/live/%s/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/%s/privkey.pem;

    # SSL Hardening (TLS 1.2 and 1.3 only)
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers HIGH:!aNULL:!MD5:!3DES;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    server_tokens off;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "0" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Rate Limiting & Proxying
    location / {
        limit_req zone=%s_limit burst=20 nodelay;

        proxy_pass http://127.0.0.1:%d;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
`, opts.AppName, opts.AppName, domain, domain, domain, domain, domain, opts.AppName, port)
}

// GenerateSystemdService returns a production Linux systemd unit file with modern Linux security sandboxing.
func GenerateSystemdService(opts ConfigOptions) string {
	user := opts.User
	if user == "" {
		user = "www-data"
	}
	exec := opts.ExecCommand
	if exec == "" {
		exec = "/usr/bin/npm start"
	}
	workDir := opts.WorkingDir
	if workDir == "" {
		workDir = "/var/www/" + opts.AppName
	}

	return fmt.Sprintf(`[Unit]
Description=%s Vibe-Coded Service (Protected by LaunchArmor)
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=%s
Group=%s
WorkingDirectory=%s
ExecStart=%s
Restart=always
RestartSec=5s
Environment=NODE_ENV=production

# ==============================================================================
# Linux Kernel Security Sandboxing (SRE / Enterprise Hardening)
# ==============================================================================
# Prevent process from gaining new privileges (blocks SUID escalation)
NoNewPrivileges=true

# Mount the entire filesystem read-only (except /dev, /proc, /sys and ReadWritePaths)
ProtectSystem=strict

# Provide private isolated /tmp directory per service
PrivateTmp=true

# Restrict access to /dev (prevent raw disk/device access)
PrivateDevices=true

# Make /home, /root and /run/user inaccessible to the process
ProtectHome=true

# Prevent changing kernel tunables (/proc/sys, /sys)
ProtectKernelTunables=true

# Prevent modifying Linux kernel modules
ProtectKernelModules=true

# Prevent modifying control groups
ProtectControlGroups=true

# Hide other users' processes and block kernel log / clock / hostname changes
ProtectProc=invisible
ProtectKernelLogs=true
ProtectClock=true
ProtectHostname=true

# Drop every Linux capability; the app binds an unprivileged port behind the proxy
CapabilityBoundingSet=
AmbientCapabilities=
RestrictSUIDSGID=true
RestrictRealtime=true
RestrictNamespaces=true
LockPersonality=true

# Only IPv4/IPv6/Unix sockets, and only syscalls a normal service needs
# (MemoryDenyWriteExecute is left off on purpose: it breaks the V8/Node.js JIT)
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
UMask=0027

# Allow read/write access ONLY to project directory
ReadWritePaths=%s

# Memory & Process limits (prevents DoS / memory exhaustion)
MemoryMax=512M
TasksMax=100

[Install]
WantedBy=multi-user.target
`, opts.AppName, user, user, workDir, exec, workDir)
}

// WriteConfigFiles writes generated configs to an output directory.
func WriteConfigFiles(outputDir string, opts ConfigOptions) error {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return err
	}

	caddyPath := filepath.Join(outputDir, "Caddyfile")
	if err := os.WriteFile(caddyPath, []byte(GenerateCaddyfile(opts)), 0644); err != nil {
		return err
	}

	nginxPath := filepath.Join(outputDir, opts.AppName+".nginx.conf")
	if err := os.WriteFile(nginxPath, []byte(GenerateNginxConfig(opts)), 0644); err != nil {
		return err
	}

	systemdPath := filepath.Join(outputDir, opts.AppName+".service")
	if err := os.WriteFile(systemdPath, []byte(GenerateSystemdService(opts)), 0644); err != nil {
		return err
	}

	return nil
}
