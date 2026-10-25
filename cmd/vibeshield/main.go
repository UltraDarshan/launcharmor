package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/UltraDarshan/vibeshield/pkg/auditor"
	"github.com/UltraDarshan/vibeshield/pkg/dbaudit"
)

const version = "0.1.0-alpha"

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
	case "version":
		fmt.Printf("VibeShield version %s (Linux/x86_64)\n", version)
	default:
		printHelp()
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
		return
	}

	fmt.Printf("\n%s🚨 Found %d potential vulnerabilities:%s\n\n", colorRed, len(report.Findings), colorReset)

	for i, f := range report.Findings {
		var sevColor string
		switch f.Severity {
		case auditor.SeverityCritical:
			sevColor = colorRed
		case auditor.SeverityHigh:
			sevColor = colorYellow
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
		fmt.Printf("\n%s[CRITICAL]%s %d table(s) can be read/written by anyone using Supabase/PostgREST anonymously!\n", colorRed, colorReset, dbResult.VulnerableTables)
	} else {
		fmt.Printf("\n%s✔ All tables have Row Level Security enabled!%s\n", colorGreen, colorReset)
	}
}

func printHelp() {
	fmt.Println("VibeShield - Security Scanner & Linux Infra Hardener for Vibe-Coded Apps")
	fmt.Println("\nUsage:")
	fmt.Println("  vibeshield scan [dir]       Scan code, secrets, and configuration rules")
	fmt.Println("  vibeshield db-audit [dir]   Audit SQL/Supabase schema migrations for open tables (RLS)")
	fmt.Println("  vibeshield version          Display version information")
}
