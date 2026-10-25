package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"

	"github.com/UltraDarshan/vibeshield/pkg/auditor"
	"github.com/UltraDarshan/vibeshield/pkg/dbaudit"
	"github.com/UltraDarshan/vibeshield/pkg/infra"
)

const version = "0.1.1"

// Names end up in file paths and nginx zone names; domains in proxy configs.
var (
	appNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)
	domainRe  = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]*$`)
)

// Terminal color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
)

func main() {
	if len(os.Args) < 2 {
		printHelp()
		os.Exit(0)
	}

	command := os.Args[1]
	switch command {
	case "scan":
		target := "."
		if len(os.Args) > 2 {
			target = os.Args[2]
		}
		runScan(target)
	case "db-audit":
		target := "."
		if len(os.Args) > 2 {
			target = os.Args[2]
		}
		runDBAudit(target)
	case "harden":
		appName := "my-app"
		port := 3000
		domain := "app.example.com"
		outputDir := "./deploy"

		if len(os.Args) > 2 {
			appName = os.Args[2]
		}
		if len(os.Args) > 3 {
			p, err := strconv.Atoi(os.Args[3])
			if err != nil || p < 1 || p > 65535 {
				fmt.Printf("Invalid port %q: must be 1-65535\n", os.Args[3])
				os.Exit(2)
			}
			port = p
		}
		if len(os.Args) > 4 {
			domain = os.Args[4]
		}
		if len(os.Args) > 5 {
			outputDir = os.Args[5]
		}
		if !appNameRe.MatchString(appName) || !domainRe.MatchString(domain) {
			fmt.Println("Invalid name or domain: use letters, digits, '-', '_' (name) and '.' (domain) only")
			os.Exit(2)
		}

		runHarden(appName, port, domain, outputDir)
	case "version":
		fmt.Printf("VibeShield version %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
	case "help", "-h", "--help":
		printHelp()
	default:
		fmt.Printf("Unknown command %q\n\n", command)
		printHelp()
		os.Exit(2)
	}
}

func runScan(target string) {
	absPath, err := filepath.Abs(target)
	if err != nil {
		fmt.Printf("Error resolving target path: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("%s[VibeShield v%s]%s Scanning project at: %s%s%s\n\n", colorCyan, version, colorReset, colorBold, absPath, colorReset)

	scanner := auditor.NewScanner(nil)
	report, err := scanner.ScanDirectory(absPath)
	if err != nil {
		fmt.Printf("Scan failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Scanned %d files (%d total in tree).\n", report.ScannedFiles, report.TotalFiles)

	if len(report.Findings) == 0 {
		fmt.Printf("\n%s✔ 0 vulnerabilities detected!%s Security Score: %s%d/100%s\n", colorGreen, colorReset, colorBold, report.Score, colorReset)
		os.Exit(0)
	}

	fmt.Printf("\n%s🚨 Found %d potential issue(s):%s\n\n", colorRed, len(report.Findings), colorReset)

	hasCriticalOrHigh := false
	for i, f := range report.Findings {
		var sevColor string
		switch f.Severity {
		case auditor.SeverityCritical:
			sevColor = colorRed
			hasCriticalOrHigh = true
		case auditor.SeverityHigh:
			sevColor = colorYellow
			hasCriticalOrHigh = true
		default:
			sevColor = colorCyan
		}

		relPath, _ := filepath.Rel(absPath, f.File)
		fmt.Printf("%d. [%s%s%s] %s%s%s\n", i+1, sevColor, f.Severity, colorReset, colorBold, f.Title, colorReset)
		fmt.Printf("   Location: %s:%d\n", relPath, f.Line)
		if f.MatchSnippet != "" {
			fmt.Printf("   Snippet:  %s\n", f.MatchSnippet)
		}
		fmt.Printf("   Details:  %s\n", f.Description)
		fmt.Printf("   %sFix:%s      %s\n\n", colorGreen, colorReset, f.Solution)
	}

	scoreColor := colorGreen
	if report.Score < 50 {
		scoreColor = colorRed
	} else if report.Score < 80 {
		scoreColor = colorYellow
	}

	fmt.Printf("=============================================\n")
	fmt.Printf("  Final Security Score: %s%s%d / 100%s\n", colorBold, scoreColor, report.Score, colorReset)
	fmt.Printf("=============================================\n")

	// Fail CI/CD step if Critical or High severity issues are found
	if hasCriticalOrHigh {
		fmt.Printf("%s[CI/CD ERROR] Build rejected due to CRITICAL/HIGH security findings.%s\n", colorRed, colorReset)
		os.Exit(1)
	}
}

func runDBAudit(target string) {
	absPath, err := filepath.Abs(target)
	if err != nil {
		fmt.Printf("Error resolving target path: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("%s[VibeShield v%s]%s Auditing database schemas in: %s%s%s\n\n", colorCyan, version, colorReset, colorBold, absPath, colorReset)

	dbResult, err := dbaudit.AuditSQLFiles(absPath)
	if err != nil {
		fmt.Printf("Database audit failed: %v\n", err)
		os.Exit(1)
	}

	if dbResult.TotalTables == 0 {
		fmt.Println("No SQL schema or migration files found in target directory.")
		return
	}

	fmt.Printf("Identified %d total tables: %s%d Protected (RLS Enabled)%s | %s%d Vulnerable (No RLS)%s\n\n",
		dbResult.TotalTables,
		colorGreen, dbResult.ProtectedTables, colorReset,
		colorRed, dbResult.VulnerableTables, colorReset)

	for _, tbl := range dbResult.Tables {
		relPath, _ := filepath.Rel(absPath, tbl.SourceFile)
		if tbl.HasRLS {
			fmt.Printf("  %s✔%s %-20s (RLS Active)   [%s:%d]\n", colorGreen, colorReset, tbl.TableName, relPath, tbl.LineNumber)
		} else {
			fmt.Printf("  %s✖%s %-20s %s(OPEN ACCESS)%s [%s:%d]\n", colorRed, colorReset, tbl.TableName, colorRed, colorReset, relPath, tbl.LineNumber)
			fmt.Printf("    %sRemediation SQL:%s %s\n", colorYellow, colorReset, tbl.FixSQL)
		}
	}

	if dbResult.VulnerableTables > 0 {
		fmt.Printf("\n%s[CRITICAL]%s %d table(s) can be read/written by anyone anonymously!\n", colorRed, colorReset, dbResult.VulnerableTables)
		fmt.Printf("%s[CI/CD ERROR] Build rejected due to open database tables (missing RLS).%s\n", colorRed, colorReset)
		os.Exit(1)
	} else {
		fmt.Printf("\n%s✔ All tables have Row Level Security enabled!%s\n", colorGreen, colorReset)
	}
}

func runHarden(appName string, port int, domain string, outputDir string) {
	fmt.Printf("%s[VibeShield v%s]%s Generating hardened Linux infrastructure configs...\n\n", colorCyan, version, colorReset)

	opts := infra.ConfigOptions{
		AppName:     appName,
		Domain:      domain,
		Port:        port,
		User:        "www-data",
		WorkingDir:  "/var/www/" + appName,
		ExecCommand: fmt.Sprintf("/usr/bin/node /var/www/%s/server.js", appName),
	}

	if err := infra.WriteConfigFiles(outputDir, opts); err != nil {
		fmt.Printf("Failed to generate configuration: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("%s✔ Configuration generated successfully in: %s%s%s\n\n", colorGreen, colorBold, outputDir, colorReset)
	fmt.Printf("  1. %sCaddyfile%s              -> Automatic HTTPS reverse proxy with HSTS, security headers, and zstd\n", colorBold, colorReset)
	fmt.Printf("  2. %s%s.nginx.conf%s      -> Nginx reverse proxy with IP rate-limiting zones\n", colorBold, appName, colorReset)
	fmt.Printf("  3. %s%s.service%s         -> Sandboxed systemd unit with Linux kernel security isolation\n\n", colorBold, appName, colorReset)
	fmt.Println("To apply on Linux:")
	fmt.Printf("  sudo cp %s/%s.service /etc/systemd/system/\n", outputDir, appName)
	fmt.Printf("  sudo systemctl daemon-reload && sudo systemctl enable --now %s\n", appName)
}

func printHelp() {
	fmt.Println("VibeShield - Security Scanner & Linux Infra Hardener for Vibe-Coded Apps")
	fmt.Println("\nUsage:")
	fmt.Println("  vibeshield scan [dir]                       Scan code, secrets, and configuration rules")
	fmt.Println("  vibeshield db-audit [dir]                   Audit SQL/Supabase schema migrations for open tables (RLS)")
	fmt.Println("  vibeshield harden [name] [port] [domain] [out-dir]")
	fmt.Println("                                              Generate hardened Linux Caddy, Nginx & systemd configs")
	fmt.Println("  vibeshield version                          Display version information")
}
