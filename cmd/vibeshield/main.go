package main

import (
	"fmt"
	"os"
)

const version = "0.1.0-alpha"

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
		fmt.Printf("[VibeShield v%s] Scanning target directory: %s\n", version, target)
		fmt.Println("Audit complete: Initial foundation initialized.")
	case "version":
		fmt.Printf("VibeShield version %s (Linux/x86_64)\n", version)
	default:
		printHelp()
	}
}

func printHelp() {
	fmt.Println("VibeShield - Security Scanner & Linux Infra Hardener for Vibe-Coded Apps")
	fmt.Println("\nUsage:")
	fmt.Println("  vibeshield scan [dir]       Scan code, secrets, and database rules")
	fmt.Println("  vibeshield harden [type]    Generate production-ready Linux configs (caddy, nginx, systemd)")
	fmt.Println("  vibeshield version          Display version information")
}
