package dbaudit

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// TableStatus tracks RLS posture of a table found in SQL schemas.
type TableStatus struct {
	TableName    string `json:"table_name"`
	HasRLS       bool   `json:"has_rls"`
	SourceFile   string `json:"source_file"`
	LineNumber   int    `json:"line_number"`
	FixSQL       string `json:"fix_sql"`
}

// DBAuditResult aggregates database audit findings.
type DBAuditResult struct {
	TotalTables      int           `json:"total_tables"`
	ProtectedTables  int           `json:"protected_tables"`
	VulnerableTables int           `json:"vulnerable_tables"`
	Tables           []TableStatus `json:"tables"`
}

var (
	createTableRegex = regexp.MustCompile(`(?i)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:public\.)?["']?([a-zA-Z0-9_]+)["']?`)
	enableRLSRegex   = regexp.MustCompile(`(?i)ALTER\s+TABLE\s+(?:ONLY\s+)?(?:public\.)?["']?([a-zA-Z0-9_]+)["']?\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY`)
)

// AuditSQLFiles scans a project directory for .sql files (migrations, schema.sql, supabase migrations)
func AuditSQLFiles(root string) (*DBAuditResult, error) {
	result := &DBAuditResult{}
	tableMap := make(map[string]*TableStatus)

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
			if err := parseSQLFile(path, tableMap); err != nil {
				return err
			}
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	for _, tbl := range tableMap {
		result.TotalTables++
		if tbl.HasRLS {
			result.ProtectedTables++
		} else {
			result.VulnerableTables++
			tbl.FixSQL = fmt.Sprintf("ALTER TABLE %s ENABLE ROW LEVEL SECURITY;", tbl.TableName)
		}
		result.Tables = append(result.Tables, *tbl)
	}

	return result, nil
}

func parseSQLFile(filePath string, tableMap map[string]*TableStatus) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Match CREATE TABLE
		if match := createTableRegex.FindStringSubmatch(line); len(match) > 1 {
			tableName := strings.ToLower(match[1])
			if _, exists := tableMap[tableName]; !exists {
				tableMap[tableName] = &TableStatus{
					TableName:  tableName,
					HasRLS:     false,
					SourceFile: filePath,
					LineNumber: lineNum,
				}
			}
		}

		// Match ALTER TABLE ... ENABLE ROW LEVEL SECURITY
		if match := enableRLSRegex.FindStringSubmatch(line); len(match) > 1 {
			tableName := strings.ToLower(match[1])
			if tbl, exists := tableMap[tableName]; exists {
				tbl.HasRLS = true
			} else {
				tableMap[tableName] = &TableStatus{
					TableName:  tableName,
					HasRLS:     true,
					SourceFile: filePath,
					LineNumber: lineNum,
				}
			}
		}
	}
	return nil
}
