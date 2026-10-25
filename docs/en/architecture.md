# LaunchArmor: Architecture & Threat Model

## 1. Overview
LaunchArmor is designed as a standalone, zero-dependency Go CLI tool to evaluate and secure rapid, AI-generated applications ("vibe-coded" systems) and their underlying Linux infrastructure.

## 2. Threat Vector Coverage

| ID | Attack Vector | Mitigation in LaunchArmor |
| :--- | :--- | :--- |
| **TV-01** | Exposed API Keys & Secrets | Line-based regex scanner detects committed `.env`, OpenAI, Stripe, and Supabase service keys. |
| **TV-02** | Unprotected Cloud Databases (IDOR) | SQL migration parser enforces Row Level Security (RLS) on PostgreSQL & Supabase. |
| **TV-03** | RCE / Command Injection | Flags unescaped `eval()` and shell execution calls in backend code. |
| **TV-04** | DoS & API Credit Depletion | Generated Nginx config enforces per-IP rate limiting (`limit_req_zone`); the optional Cloudflare Worker adds edge rate limiting. |
| **TV-05** | Host Privilege Escalation (Linux VPS) | Generates `systemd` units with `NoNewPrivileges`, `ProtectSystem=strict`, private `/tmp`, an empty capability set and a syscall allow-list (`systemd-analyze security`: 1.5 OK). |

---

## 3. Linux Infrastructure Sandboxing Architecture

When deploying AI-generated apps to a Linux server, typical amateurs run apps directly as `root` or without process isolation. LaunchArmor generates kernel-level sandboxing configurations:

```
+----------------------------------------------------------------+
|                        Linux Host (Kernel)                     |
|                                                                |
|  +--------------------+          +--------------------------+  |
|  | Caddy / Nginx      |          | Systemd Unit (Sandboxed) |  |
|  | - Strict HTTPS     |  Proxy   | - NoNewPrivileges=true   |  |
|  | - Rate Limit(Nginx)| -------> | - ProtectSystem=strict   |  |
|  | - HSTS / Headers   |  :3000   | - PrivateTmp=true        |  |
|  +--------------------+          | - MemoryMax=512M         |  |
|                                  +--------------------------+  |
+----------------------------------------------------------------+
```

### Key Linux Directives Used:
1. `NoNewPrivileges=true`: Disallows child processes from acquiring new privileges through `setuid` or `setgid` binaries.
2. `ProtectSystem=strict`: Mounts the entire filesystem read-only except `ReadWritePaths` (the app directory).
3. `PrivateTmp=true`: Allocates a private file namespace for `/tmp`, preventing cross-process temporary file attacks.
4. `ProtectHome=true`: Makes `/home`, `/root` and `/run/user` inaccessible to the service.
5. `MemoryMax=512M` & `TasksMax=100`: Prevents fork-bombs and memory leaks from crashing the host.
6. `CapabilityBoundingSet=` & `SystemCallFilter=@system-service`: Drops all Linux capabilities and restricts the process to the syscalls a normal service needs. `MemoryDenyWriteExecute` is intentionally omitted because it breaks the V8/Node.js JIT.
