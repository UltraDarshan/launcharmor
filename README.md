# VibeShield (バイブ・シールド)

> **Zero-cost, developer-first security scanner & Linux infrastructure hardener for AI vibe-coded applications.**

[![Go Version](https://img.shields.io/badge/go-1.26+-00ADD8.svg)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## 🎯 Overview

AI coding assistants (Cursor, Bolt, v0, Lovable, Claude) allow anyone to build and ship applications rapidly. However, **vibe-coded apps frequently suffer from critical security blindspots**:
- Hardcoded API keys (OpenAI, Stripe, database credentials).
- Unprotected databases (missing PostgreSQL/Supabase Row-Level Security).
- Missing Linux server hardening (running apps as root, open ports, missing rate-limiting).
- High risk of automated scraping and AI API credit exhaustion.

**VibeShield** provides an automated, single-binary security auditor and Linux infrastructure hardening suite designed specifically for rapid AI-generated applications.

---

## 🚀 Key Features

1. **Instant Project Audit**: Detects leaked secrets, insecure CORS, and dangerous patterns before deploying.
2. **Database RLS Verification**: Inspects database schemas to ensure row-level access control is active.
3. **Linux Infrastructure Hardener**: Generates production-ready, hardened Caddy/Nginx reverse proxy configurations and sandboxed `systemd` service files.
4. **Zero External Dependencies**: Distributed as a single, lightweight Go binary with zero runtime overhead.

---

## 🛠️ Quick Start

```bash
# Clone the repository
git clone https://github.com/UltraDarshan/vibeshield.git
cd vibeshield

# Run scan on your project
go run ./cmd/vibeshield scan /path/to/vibe-coded-project
```

---

## 🇯PN 日本語概要 (Japanese Overview)

VibeShieldは、AIツール（Cursor、v0、Bolt等）で高速開発されたWebアプリケーション向けのセキュリティ監査およびLinuxインフラ保護ツールです。
APIキーの露出、データベースのRLS（行レベルセキュリティ）未設定、不適切なLinuxプロセス権限などの脆弱性を瞬時に検出し、本番環境向けのセキュアな構成（Caddy/Nginx、systemdサンドボックス）を自動生成します。

---

## 📄 License
MIT License.
