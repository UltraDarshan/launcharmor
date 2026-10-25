# VibeShield: アーキテクチャおよび脅威モデル (Architecture & Threat Model)

## 1. 概要 (Overview)
VibeShieldは、AIツール（Cursor、v0、Bolt等）によって高速開発された「バイブコーディング（Vibe-coded）」アプリおよびそのLinuxインフラを自動保護するためのGo言語製セキュリティツールです。外部依存関係なしで単一のバイナリとして動作します。

## 2. 対策する脅威ベクトル (Threat Vectors)

| ID | 攻撃ベクトル (Threat) | VibeShieldの対策 (Mitigation) |
| :--- | :--- | :--- |
| **TV-01** | APIキー・クレデンシャルの流出 | 静的解析エンジンにより、コミットされた `.env`、OpenAI、Stripe、Supabase秘密鍵を検出。 |
| **TV-02** | データベースの不正アクセス (IDOR) | SQLファイルを走査し、PostgreSQLおよびSupabaseの行レベルセキュリティ (RLS) 未適用テーブルを検出。 |
| **TV-03** | リモートコード実行 (RCE) | バックエンド内のエスケープされていない `eval()` や危険なシェル実行関数を検出。 |
| **TV-04** | APIクレジット枯渇・DoS攻撃 | Caddy/Nginx向けのリバースプロキシ設定を自動生成し、IPレート制限 (`limit_req_zone`) を強制適用。 |
| **TV-05** | Linuxホストの特権昇格・侵害 | `NoNewPrivileges`、`ProtectSystem=strict`、専用 `/tmp` 名前空間を含む安全な `systemd` ユニットファイルを自動生成。 |

---

## 3. Linuxインフラ・サンドボックス設計 (Linux Sandboxing Architecture)

AIによって生成されたコードは、未知の脆弱性を含む可能性があります。本番Linux環境で安全に稼働させるため、Linuxカーネルのセキュリティ機能（名前空間、cgroups、アクセス制御）を活用した多層防御を実現します。

```
+----------------------------------------------------------------+
|                        Linux Host (Kernel)                     |
|                                                                |
|  +--------------------+          +--------------------------+  |
|  | Caddy / Nginx      |          | Systemd Unit (Sandboxed) |  |
|  | - 常時HTTPS化      |  Proxy   | - NoNewPrivileges=true   |  |
|  | - IPレート制限     | -------> | - ProtectSystem=strict   |  |
|  | - HSTS / CSP       |  :3000   | - PrivateTmp=true        |  |
|  +--------------------+          | - MemoryMax=512M         |  |
|                                  +--------------------------+  |
+----------------------------------------------------------------+
```

### 使用しているLinuxカーネル保護ディレクティブ:
1. `NoNewPrivileges=true`: プロセスおよび子プロセスによる `setuid`/`setgid` 特権昇格を完全に禁止。
2. `ProtectSystem=strict`: `/usr`、`/boot`、`/etc` などのシステムディレクトリを完全な読み取り専用としてマウント。
3. `PrivateTmp=true`: サービス専用の独立したファイルシステム名前空間を `/tmp` に割り当て、プロセス間の一時ファイル干渉を防止。
4. `ProtectHome=true`: `/home` ディレクトリをマウント解除し、他ユーザーの個人データへのアクセスを遮断。
5. `MemoryMax=512M` & `TasksMax=100`: メモリ枯渇やフォークボムによるLinuxホスト全体の停止（DoS）を防止。
