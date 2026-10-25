# VibeShield (バイブ・シールド)

> **Zero-cost, developer-first security scanner & Linux infrastructure hardener for AI vibe-coded applications.**  
> *AIバイブコーディングアプリ向け、ゼロコスト・開発者主導のセキュリティスキャナー兼Linuxインフラ保護スイート。*

[![Go Version](https://img.shields.io/badge/go-1.26+-00ADD8.svg)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Build & Test](https://img.shields.io/badge/tests-passing-brightgreen.svg)]()

---

## 🎯 Overview

AI coding tools (Cursor, Bolt, v0, Lovable, Claude) allow anyone to prototype and ship applications in minutes. However, **vibe-coded apps frequently introduce critical security vulnerabilities**:
- Exposed API keys (OpenAI, Stripe, database connection strings).
- Unprotected cloud databases (missing PostgreSQL/Supabase Row Level Security).
- Dangerous execution functions (`eval()`, command injection).
- Unhardened Linux servers (apps run directly as `root` without reverse proxies or rate limits).

**VibeShield** is an open-core, single-binary security scanner and Linux infrastructure hardener written in Go with **zero runtime dependencies**.

---

## 🚀 Commands & Usage

### 1. Security Scan (`vibeshield scan`)
Audits source code files, configurations, and environment files for leaked credentials and risky patterns:
```bash
./bin/vibeshield scan /path/to/project
```

### 2. Database RLS Verification (`vibeshield db-audit`)
Parses database migrations and SQL schema files to verify that all tables have Row Level Security enabled:
```bash
./bin/vibeshield db-audit /path/to/project
```

### 3. Linux Infrastructure Hardening (`vibeshield harden`)
Generates production-grade, hardened Caddy / Nginx reverse proxy configs and sandboxed Linux `systemd` service files:
```bash
./bin/vibeshield harden myapp 3000 myapp.com ./deploy
```

---

## 🛠️ Build & Development

```bash
# Clone the repository
git clone git@github.com:UltraDarshan/vibeshield.git
cd vibeshield

# Build binary
make build

# Run automated tests
make test
```

---

## 🇯PN 日本語概要 (Overview for Japan Tech Infrastructure)

VibeShieldは、AIツール（Cursor、v0、Bolt等）で高速開発されたWebアプリケーション向けのセキュリティ監査およびLinuxインフラ保護ツールです。
APIキーの露出、データベースのRLS（行レベルセキュリティ）未設定、不適切なLinuxプロセス権限などの脆弱性を瞬時に検出し、本番環境向けのセキュアな構成（Caddy/Nginx、systemdサンドボックス）を自動生成します。

詳細なアーキテクチャおよび脅威モデルは [docs/ja/architecture.md](docs/ja/architecture.md) をご参照ください。

---

## 📄 License
MIT License.
