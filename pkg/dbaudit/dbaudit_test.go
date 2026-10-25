package dbaudit

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAuditSQLFiles(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "vibeshield-dbtest-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	schemaPath := filepath.Join(tempDir, "schema.sql")
	sqlContent := `
CREATE TABLE customers (id INT, email TEXT);
CREATE TABLE transactions (id INT, amount NUMERIC);
ALTER TABLE transactions ENABLE ROW LEVEL SECURITY;
`
	if err := os.WriteFile(schemaPath, []byte(sqlContent), 0644); err != nil {
		t.Fatalf("Failed to write schema file: %v", err)
	}

	result, err := AuditSQLFiles(tempDir)
	if err != nil {
		t.Fatalf("AuditSQLFiles failed: %v", err)
	}

	if result.TotalTables != 2 {
		t.Errorf("Expected 2 tables, got %d", result.TotalTables)
	}

	if result.ProtectedTables != 1 {
		t.Errorf("Expected 1 protected table, got %d", result.ProtectedTables)
	}

	if result.VulnerableTables != 1 {
		t.Errorf("Expected 1 vulnerable table, got %d", result.VulnerableTables)
	}
}
