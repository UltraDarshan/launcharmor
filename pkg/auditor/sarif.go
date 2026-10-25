package auditor

import (
	"encoding/json"
	"path/filepath"
	"sort"
)

var securitySeverity = map[Severity]string{SeverityCritical: "9.5", SeverityHigh: "7.5", SeverityMedium: "5.0", SeverityLow: "2.0"}

func sarifLevel(s Severity) string {
	switch s {
	case SeverityCritical, SeverityHigh:
		return "error"
	case SeverityMedium:
		return "warning"
	}
	return "note"
}

// SARIF renders findings as SARIF 2.1.0 for GitHub code scanning. Paths are made relative to root.
func SARIF(findings []Finding, root, version string) ([]byte, error) {
	type m = map[string]any
	rules := map[string]m{}
	results := []m{}
	for _, f := range findings {
		if _, ok := rules[f.RuleID]; !ok {
			rules[f.RuleID] = m{
				"id":                   f.RuleID,
				"name":                 f.Title,
				"shortDescription":     m{"text": f.Title},
				"fullDescription":      m{"text": f.Description},
				"help":                 m{"text": f.Solution},
				"defaultConfiguration": m{"level": sarifLevel(f.Severity)},
				"properties":           m{"security-severity": securitySeverity[f.Severity], "tags": []string{"security"}},
			}
		}
		rel, err := filepath.Rel(root, f.File)
		if err != nil {
			rel = f.File
		}
		results = append(results, m{
			"ruleId":  f.RuleID,
			"level":   sarifLevel(f.Severity),
			"message": m{"text": f.Title + ": " + f.Description + " Fix: " + f.Solution},
			"locations": []m{{"physicalLocation": m{
				"artifactLocation": m{"uri": filepath.ToSlash(rel)},
				"region":           m{"startLine": max(1, f.Line)},
			}}},
		})
	}
	ids := make([]string, 0, len(rules))
	for id := range rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	ruleList := make([]m, 0, len(ids))
	for _, id := range ids {
		ruleList = append(ruleList, rules[id])
	}
	return json.MarshalIndent(m{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []m{{
			"tool": m{"driver": m{
				"name":           "LaunchArmor",
				"version":        version,
				"informationUri": "https://github.com/UltraDarshan/launcharmor",
				"rules":          ruleList,
			}},
			"results": results,
		}},
	}, "", "  ")
}
