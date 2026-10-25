package auditor

// Finding represents an identified security or infrastructure issue.
type Finding struct {
	RuleID       string   `json:"rule_id"`
	Title        string   `json:"title"`
	Severity     Severity `json:"severity"`
	File         string   `json:"file"`
	Line         int      `json:"line"`
	Description  string   `json:"description"`
	Solution     string   `json:"solution"`
	MatchSnippet string   `json:"match_snippet"`
}

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

// Report aggregates scan results.
type Report struct {
	TargetDir    string    `json:"target_dir"`
	TotalFiles   int       `json:"total_files"`
	ScannedFiles int       `json:"scanned_files"`
	Findings     []Finding `json:"findings"`
	Score        int       `json:"score"`
}
