# LaunchArmor (ローンチ・アーマー)

> **Zero-cost, developer-first security scanner & Linux infrastructure hardener for AI vibe-coded applications.**  
> *AIバイブコーディングアプリ向け、ゼロコスト・開発者主導のセキュリティスキャナー兼Linuxインフラ保護スイート。*

[![Go Version](https://img.shields.io/badge/go-1.26+-00ADD8.svg)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![CI](https://github.com/UltraDarshan/launcharmor/actions/workflows/ci.yml/badge.svg)](https://github.com/UltraDarshan/launcharmor/actions/workflows/ci.yml)

---

## 🎯 Overview

AI coding tools (Cursor, Bolt, v0, Lovable, Claude) allow anyone to prototype and ship applications in minutes. However, **vibe-coded apps frequently introduce critical security vulnerabilities**:
- Exposed API keys (OpenAI, Stripe, database connection strings).
- Unprotected cloud databases (missing PostgreSQL/Supabase Row Level Security).
- Dangerous execution functions (`eval()`, command injection).
- Unhardened Linux servers (apps run directly as `root` without reverse proxies or rate limits).

**LaunchArmor** is an open-core, single-binary security scanner and Linux infrastructure hardener written in Go with **zero runtime dependencies**.

---

## 📦 Install

```bash
curl -fsSL https://raw.githubusercontent.com/UltraDarshan/launcharmor/main/install.sh | bash
# or, with Go installed:
go install github.com/UltraDarshan/launcharmor/cmd/launcharmor@latest
```

Prebuilt binaries for Linux, macOS (amd64/arm64) and Windows are on the [releases page](https://github.com/UltraDarshan/launcharmor/releases).

---

## 🚀 Commands & Usage

### 1. Security Scan (`launcharmor scan`)
Finds the leaks that actually happen in AI-built apps. Exits non-zero on any CRITICAL/HIGH finding, so it can gate CI:
```bash
launcharmor scan /path/to/project
launcharmor scan . --format sarif > launcharmor.sarif   # or --format json
```

| Rule | Detects | Severity |
| :--- | :--- | :--- |
| VS-000 | Committed `.env` files (templates like `.env.example` are fine) | High |
| VS-001 | OpenAI keys, including `sk-proj-` / `sk-svcacct-` | Critical |
| VS-002 | Stripe live secret and restricted keys | Critical |
| VS-003 | Supabase **service_role** JWTs (the JWT is decoded; public anon keys are not flagged) | Critical |
| VS-004 | Dynamic code / shell execution | High |
| VS-005 | Wildcard CORS | Medium |
| VS-006 | Anthropic API keys | Critical |
| VS-007 | AWS access keys | Critical |
| VS-008 | Google API keys (Gemini/Maps; Firebase web keys are public by design) | Medium |
| VS-009 | GitHub tokens | Critical |
| VS-010 | Private keys | Critical |
| VS-011 | Database URLs with a real password on a remote host | High |
| VS-012 | Secrets in browser-bundled env vars (`NEXT_PUBLIC_`, `VITE_`, `EXPO_PUBLIC_`…) | Critical |
| VS-013 | Slack tokens | High |
| VS-014 | Resend API keys | Critical |
| VS-015 | Groq API keys | Critical |
| VS-016 | PostHog keys | High |
| VS-017 | Perplexity AI keys (`pplx-`) | Critical |
| VS-018 | Hugging Face tokens (`hf_`) | High |
| VS-020 | Firebase rules with `if true` / `".read": true` | Critical |

Placeholders (`sk-xxxx`, `your-api-key`), local dev databases and gitignored `.env` files are skipped, and secrets are **masked in all output** so findings never re-leak keys into CI logs. False positive? Add `launcharmor:ignore` in a comment on that line.

### 2. Database RLS Verification (`launcharmor db-audit`)
Replays your SQL / Supabase migrations in order and reports every `public` table anyone can reach through the Supabase API:
- tables without Row Level Security (or with RLS disabled again later),
- RLS tables with a policy like `FOR UPDATE USING (true)` that lets anyone change every row,
- `FOR SELECT USING (true)` policies, as a warning (fine for public posts, not for user data).

Each finding comes with fix SQL that is checked to run on Postgres 17.
```bash
launcharmor db-audit /path/to/project
```

### 3. Linux Infrastructure Hardening (`launcharmor harden`)
Generates hardened Caddy / Nginx reverse proxy configs and a sandboxed `systemd` unit (`systemd-analyze security` exposure score: **1.5 OK**):
```bash
launcharmor harden <name> <port> <domain> [out-dir]   # e.g. launcharmor harden myapp 3000 myapp.com ./deploy
```

### 4. Git Pre-Commit Hook (`launcharmor install-hook`)
Blocks leaked secrets and risky code before `git commit` allows them into your repository history:
```bash
launcharmor install-hook
```

### 5. GitHub Action
```yaml
- uses: actions/checkout@v4
- name: LaunchArmor security audit
  uses: UltraDarshan/launcharmor@main
  with:
    target_dir: '.'
    audit_db: 'true'
    sarif: 'true'   # optional: show findings in the Security tab (needs permissions: security-events: write)
```

### 5. Edge firewall (Cloudflare Worker, free tier)
[`pkg/infra/cloudflare-worker.js`](pkg/infra/cloudflare-worker.js) blocks exploit probes (`/.env`, `/.git`, `wp-admin`), rate-limits per IP, and masks leaked OpenAI/Stripe keys in responses. Set `ORIGIN_HOSTNAME` in [`wrangler.toml`](pkg/infra/wrangler.toml), then `cd pkg/infra && npx wrangler deploy`.

---

## 🛠️ Build & Development

```bash
# Clone the repository
git clone https://github.com/UltraDarshan/launcharmor.git
cd launcharmor

# Build binary
make build

# Run automated tests
make test
```

---

## 🇯🇵 日本語概要 (Overview for Japan Tech Infrastructure)

LaunchArmorは、AIツール（Cursor、v0、Bolt等）で高速開発されたWebアプリケーション向けのセキュリティ監査およびLinuxインフラ保護ツールです。
APIキーの露出、データベースのRLS（行レベルセキュリティ）未設定、不適切なLinuxプロセス権限などの脆弱性を瞬時に検出し、本番環境向けのセキュアな構成（Caddy/Nginx、systemdサンドボックス）を自動生成します。

詳細なアーキテクチャおよび脅威モデルは [docs/ja/architecture.md](docs/ja/architecture.md) をご参照ください。

---

## 📄 License
MIT License. See [LICENSE](LICENSE).
