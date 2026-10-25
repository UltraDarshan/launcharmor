package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/UltraDarshan/vibeshield/pkg/auditor"
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

	// Print Score
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

func printHelp() {
	fmt.Println("VibeShield - Security Scanner & Linux Infra Hardener for Vibe-Coded Apps")
	fmt.Println("\nUsage:")
	fmt.Println("  vibeshield scan [dir]       Scan code, secrets, and configuration rules")
	fmt.Println("  vibeshield version          Display version information")
}
