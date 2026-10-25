package dbaudit

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/UltraDarshan/vibeshield/pkg/auditor"
)

// Issue is a problem with a table's access rules beyond plain "RLS off".
type Issue struct {
	Severity string `json:"severity"` // CRITICAL fails the audit; WARNING is shown but does not
	Message  string `json:"message"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	FixSQL   string `json:"fix_sql"`
}

// TableStatus tracks RLS posture of a table found in SQL schemas.
type TableStatus struct {
	TableName  string  `json:"table_name"`
	HasRLS     bool    `json:"has_rls"`
	SourceFile string  `json:"source_file"`
	LineNumber int     `json:"line_number"`
	FixSQL     string  `json:"fix_sql"`
	Issues     []Issue `json:"issues"`

	policies map[string]policy
}

// Vulnerable reports whether anyone can read or write rows they should not.
func (t TableStatus) Vulnerable() bool {
	if !t.HasRLS {
		return true
	}
	for _, i := range t.Issues {
		if i.Severity == "CRITICAL" {
			return true
		}
	}
	return false
}

// DBAuditResult aggregates database audit findings.
type DBAuditResult struct {
	TotalTables      int           `json:"total_tables"`
	ProtectedTables  int           `json:"protected_tables"`
	VulnerableTables int           `json:"vulnerable_tables"`
	Tables           []TableStatus `json:"tables"`
}

type policy struct {
	name, command, roles string
	usingTrue, checkTrue bool
	file                 string
	line                 int
}

const ident = `(?:"?(\w+)"?\.)?"?(\w+)"?` // optional schema, then table

var (
	createTableRe = regexp.MustCompile(`(?i)^CREATE\s+(?:UNLOGGED\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?` + ident)
	tempTableRe   = regexp.MustCompile(`(?i)^CREATE\s+(?:GLOBAL\s+|LOCAL\s+)?TEMP(?:ORARY)?\s+TABLE`)
	alterRLSRe    = regexp.MustCompile(`(?i)^ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?` + ident + `\s+(ENABLE|DISABLE)\s+ROW\s+LEVEL\s+SECURITY`)
	dropTableRe   = regexp.MustCompile(`(?i)^DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?` + ident)
	createPolRe   = regexp.MustCompile(`(?is)^CREATE\s+POLICY\s+("[^"]+"|\w+)\s+ON\s+` + ident + `(.*)$`)
	dropPolRe     = regexp.MustCompile(`(?i)^DROP\s+POLICY\s+(?:IF\s+EXISTS\s+)?("[^"]+"|\w+)\s+ON\s+` + ident)
	polForRe      = regexp.MustCompile(`(?i)\bFOR\s+(ALL|SELECT|INSERT|UPDATE|DELETE)\b`)
	polToRe       = regexp.MustCompile(`(?i)\bTO\s+([\w\s,"]+?)(?:\s+USING|\s+WITH|$)`)
	usingTrueRe   = regexp.MustCompile(`(?i)\bUSING\s*\(\s*\(?\s*true\s*\)?\s*\)`)
	checkTrueRe   = regexp.MustCompile(`(?i)\bWITH\s+CHECK\s*\(\s*\(?\s*true\s*\)?\s*\)`)
	restrictiveRe = regexp.MustCompile(`(?i)\bAS\s+RESTRICTIVE\b`)
)

// AuditSQLFiles scans a project directory for .sql files (migrations, schema.sql, supabase migrations).
// Files are read in path order, which matches timestamp-named migration order.
func AuditSQLFiles(root string) (*DBAuditResult, error) {
	result := &DBAuditResult{}
	tables := make(map[string]*TableStatus)

	if _, err := os.Stat(root); err != nil {
		return nil, err
	}

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			name := info.Name()
			if name == ".git" || name == "node_modules" || name == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.ToLower(filepath.Ext(path)) == ".sql" {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, st := range splitStatements(string(data)) {
				apply(st, path, tables)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	for _, tbl := range tables {
		evaluate(tbl)
		result.TotalTables++
		if tbl.Vulnerable() {
			result.VulnerableTables++
		} else {
			result.ProtectedTables++
		}
		result.Tables = append(result.Tables, *tbl)
	}
	sort.Slice(result.Tables, func(i, j int) bool { return result.Tables[i].TableName < result.Tables[j].TableName })
	return result, nil
}

// exposed reports whether Supabase's API can reach a table in this schema (only public by default).
func exposed(schema string) bool {
	return schema == "" || strings.EqualFold(schema, "public")
}

func apply(st statement, file string, tables map[string]*TableStatus) {
	text := st.text
	if tempTableRe.MatchString(text) {
		return
	}
	if m := createTableRe.FindStringSubmatch(text); m != nil {
		name := strings.ToLower(m[2])
		if exposed(m[1]) && tables[name] == nil {
			tables[name] = &TableStatus{TableName: name, SourceFile: file, LineNumber: st.line, policies: map[string]policy{}}
		}
		return
	}
	if m := alterRLSRe.FindStringSubmatch(text); m != nil {
		if tbl := tables[strings.ToLower(m[2])]; tbl != nil && exposed(m[1]) {
			tbl.HasRLS = strings.EqualFold(m[3], "ENABLE")
		}
		return
	}
	if m := dropTableRe.FindStringSubmatch(text); m != nil && exposed(m[1]) {
		delete(tables, strings.ToLower(m[2]))
		return
	}
	if m := dropPolRe.FindStringSubmatch(text); m != nil {
		if tbl := tables[strings.ToLower(m[3])]; tbl != nil {
			delete(tbl.policies, strings.Trim(m[1], `"`))
		}
		return
	}
	if m := createPolRe.FindStringSubmatch(text); m != nil {
		tbl := tables[strings.ToLower(m[3])]
		if tbl == nil || restrictiveRe.MatchString(m[4]) { // restrictive policies only ever narrow access
			return
		}
		p := policy{name: strings.Trim(m[1], `"`), command: "ALL", roles: "public", file: file, line: st.line,
			usingTrue: usingTrueRe.MatchString(m[4]), checkTrue: checkTrueRe.MatchString(m[4])}
		if f := polForRe.FindStringSubmatch(m[4]); f != nil {
			p.command = strings.ToUpper(f[1])
		}
		if r := polToRe.FindStringSubmatch(m[4]); r != nil {
			p.roles = strings.ToLower(strings.Join(strings.Fields(strings.ReplaceAll(r[1], `"`, "")), ""))
		}
		tbl.policies[p.name] = p
	}
}

// evaluate turns the final RLS state and policies of a table into issues.
func evaluate(tbl *TableStatus) {
	if !tbl.HasRLS {
		tbl.FixSQL = fmt.Sprintf("ALTER TABLE %s ENABLE ROW LEVEL SECURITY;", tbl.TableName)
		return
	}
	names := make([]string, 0, len(tbl.policies))
	for n := range tbl.policies {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		p := tbl.policies[n]
		if !(p.usingTrue || p.checkTrue) || p.roles == "service_role" {
			continue
		}
		who := "anyone, even logged out,"
		if p.roles == "authenticated" {
			who = "any logged-in user"
		}
		drop := fmt.Sprintf(`DROP POLICY "%s" ON %s;`, p.name, tbl.TableName)
		if p.command == "SELECT" {
			// Often intended (public posts), so a warning rather than a failure
			if p.roles != "authenticated" {
				tbl.Issues = append(tbl.Issues, Issue{Severity: "WARNING", File: p.file, Line: p.line,
					Message: fmt.Sprintf("policy %q lets %s read every row; fine for public content, not for user data", p.name, who),
					FixSQL:  drop + fmt.Sprintf(` CREATE POLICY "owner can read" ON %s FOR SELECT TO authenticated USING (auth.uid() = user_id);`, tbl.TableName)})
			}
			continue
		}
		// Postgres only allows USING on DELETE and only WITH CHECK on INSERT, so the fix must match
		owner, action := "USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id)", "read, change and delete every row"
		switch p.command {
		case "INSERT":
			owner, action = "WITH CHECK (auth.uid() = user_id)", "insert rows on behalf of any user"
		case "UPDATE":
			action = "change every row"
		case "DELETE":
			owner, action = "USING (auth.uid() = user_id)", "delete every row"
		}
		tbl.Issues = append(tbl.Issues, Issue{Severity: "CRITICAL", File: p.file, Line: p.line,
			Message: fmt.Sprintf("policy %q (FOR %s) lets %s %s", p.name, p.command, who, action),
			FixSQL:  drop + fmt.Sprintf(` CREATE POLICY "owner only" ON %s FOR %s TO authenticated %s; -- adjust user_id to your owner column`, tbl.TableName, p.command, owner)})
	}
}

type statement struct {
	text string
	line int
}

// splitStatements splits SQL on top-level semicolons, skipping comments, quoted strings and
// $tag$ function bodies, and records the line each statement starts on.
func splitStatements(sql string) []statement {
	var out []statement
	var cur strings.Builder
	line, start := 1, 0
	flush := func() {
		if t := strings.TrimSpace(cur.String()); t != "" {
			out = append(out, statement{text: strings.Join(strings.Fields(t), " "), line: start})
		}
		cur.Reset()
		start = 0
	}
	for i := 0; i < len(sql); i++ {
		c := sql[i]
		switch {
		case c == '-' && strings.HasPrefix(sql[i:], "--"):
			for i < len(sql) && sql[i] != '\n' {
				i++
			}
			i-- // let the newline be counted below
			continue
		case c == '/' && strings.HasPrefix(sql[i:], "/*"):
			end := strings.Index(sql[i+2:], "*/")
			if end < 0 {
				end = len(sql) - i - 2
			}
			line += strings.Count(sql[i:i+2+end], "\n")
			i += end + 3
			continue
		case c == '\'':
			j := i + 1
			for j < len(sql)-1 && sql[j] != '\'' {
				j++
			}
			seg := sql[i : j+1]
			line += strings.Count(seg, "\n")
			if start == 0 {
				start = line
			}
			cur.WriteString(seg)
			i = j
			continue
		case c == '$':
			if tag := dollarTagRe.FindString(sql[i:]); tag != "" {
				end := strings.Index(sql[i+len(tag):], tag)
				if end < 0 {
					end = len(sql) - i - len(tag)
				}
				body := sql[i:min(len(sql), i+2*len(tag)+end)]
				line += strings.Count(body, "\n")
				cur.WriteString(" $body$ ")
				i += len(body) - 1
				continue
			}
		case c == ';':
			flush()
			continue
		}
		if c == '\n' {
			line++
		}
		if start == 0 && c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			start = line
		}
		cur.WriteByte(c)
	}
	flush()
	return out
}

var dollarTagRe = regexp.MustCompile(`^\$\w*\$`)

// Findings converts the audit into scanner findings so both commands share JSON/SARIF output.
func (r *DBAuditResult) Findings() []auditor.Finding {
	var out []auditor.Finding
	for _, t := range r.Tables {
		if !t.HasRLS {
			out = append(out, auditor.Finding{RuleID: "VS-DB-001", Title: "Table Without Row Level Security", Severity: auditor.SeverityCritical,
				File: t.SourceFile, Line: t.LineNumber, MatchSnippet: t.TableName,
				Description: "Table " + t.TableName + " has no RLS, so anyone with your public anon key can read and write every row.",
				Solution:    t.FixSQL + " Then add policies for who may read/write."})
		}
		for _, i := range t.Issues {
			f := auditor.Finding{RuleID: "VS-DB-002", Title: "Policy Grants Write Access to Every Row", Severity: auditor.SeverityCritical,
				File: i.File, Line: i.Line, MatchSnippet: t.TableName, Description: "Table " + t.TableName + ": " + i.Message + ".", Solution: i.FixSQL}
			if i.Severity != "CRITICAL" {
				f.RuleID, f.Title, f.Severity = "VS-DB-003", "Policy Makes Every Row Publicly Readable", auditor.SeverityMedium
			}
			out = append(out, f)
		}
	}
	return out
}
