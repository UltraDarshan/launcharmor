# VibeShield: Architecture & Threat Model

## 1. Overview
VibeShield is designed as a standalone, zero-dependency Go CLI tool to evaluate and secure rapid, AI-generated applications ("vibe-coded" systems) and their underlying Linux infrastructure.

## 2. Threat Vector Coverage

| ID | Attack Vector | Mitigation in VibeShield |
| :--- | :--- | :--- |
| **TV-01** | Exposed API Keys & Secrets | Static AST & regex scanner detects committed `.env`, OpenAI, Stripe, and Supabase service keys. |
| **TV-02** | Unprotected Cloud Databases (IDOR) | SQL migration parser enforces Row Level Security (RLS) on PostgreSQL & Supabase. |
| **TV-03** | RCE / Command Injection | Flags unescaped `eval()` and shell execution calls in backend code. |
| **TV-04** | DoS & API Credit Depletion | Automated reverse-proxy rules enforce IP rate-limiting (`limit_req_zone`). |
| **TV-05** | Host Privilege Escalation (Linux VPS) | Generates `systemd` unit files enforcing `NoNewPrivileges`, `ProtectSystem=strict`, and private `/tmp`. |

---

## 3. Linux Infrastructure Sandboxing Architecture

When deploying AI-generated apps to a Linux server, typical amateurs run apps directly as `root` or without process isolation. VibeShield generates kernel-level sandboxing configurations:

```
+----------------------------------------------------------------+
|                        Linux Host (Kernel)                     |
|                                                                |
|  +--------------------+          +--------------------------+  |
|  | Caddy / Nginx      |          | Systemd Unit (Sandboxed) |  |
|  | - Strict HTTPS     |  Proxy   | - NoNewPrivileges=true   |  |
|  | - Rate Limiting    | -------> | - ProtectSystem=strict   |  |
|  | - HSTS / CSP       |  :3000   | - PrivateTmp=true        |  |
|  +--------------------+          | - MemoryMax=512M         |  |
|                                  +--------------------------+  |
+----------------------------------------------------------------+
```

### Key Linux Directives Used:
1. `NoNewPrivileges=true`: Disallows child processes from acquiring new privileges through `setuid` or `setgid` binaries.
2. `ProtectSystem=strict`: Mounts `/usr`, `/boot`, `/etc` as read-only.
3. `PrivateTmp=true`: Allocates a private file namespace for `/tmp`, preventing cross-process temporary file attacks.
4. `ProtectHome=true`: Completely unmounts `/home` from the service's mount namespace.
5. `MemoryMax=512M` & `TasksMax=100`: Prevents fork-bombs and memory leaks from crashing the host.
