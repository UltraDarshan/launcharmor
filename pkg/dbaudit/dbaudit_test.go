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
-- CREATE TABLE commented_out (id INT);
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

func TestAuditSQLFilesSchemaQualified(t *testing.T) {
	dir := t.TempDir()
	sql := `CREATE TABLE IF NOT EXISTS "public"."posts" (id INT);
ALTER TABLE ONLY public.posts ENABLE ROW LEVEL SECURITY;
CREATE TABLE auth.sessions (id INT);
`
	if err := os.WriteFile(filepath.Join(dir, "m.sql"), []byte(sql), 0644); err != nil {
		t.Fatal(err)
	}
	result, err := AuditSQLFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	// auth.sessions is outside the API-exposed public schema, so only posts counts
	if result.TotalTables != 1 || result.Tables[0].TableName != "posts" || !result.Tables[0].HasRLS {
		t.Errorf("unexpected tables: %+v", result.Tables)
	}
	if _, err := AuditSQLFiles(filepath.Join(dir, "missing")); err == nil {
		t.Error("expected error for missing target dir")
	}
}

func TestAuditPolicies(t *testing.T) {
	dir := t.TempDir()
	write := func(name, sql string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(sql), 0644); err != nil {
			t.Fatal(err)
		}
	}
	write("001_init.sql", `
create table public.profiles (
  id uuid primary key, -- the owner; a ; in a comment must not split
  bio text default 'hello; world'
);
alter table public.profiles
  enable row level security;
create policy "Anyone can update" on public.profiles
  for update using (true);

create table posts (id uuid, user_id uuid);
alter table posts enable row level security;
create policy "Public posts" on posts for select using (true);

create table notes (id uuid);
alter table notes enable row level security;
create policy "temp" on notes for all to authenticated using (true) with check (true);

create table audit_log (id uuid);
alter table audit_log enable row level security;
create policy "server only" on audit_log for all to service_role using (true);

create or replace function bump() returns trigger as $$
begin
  update posts set id = id; -- semicolons inside a function body
  return new;
end;
$$ language plpgsql;
`)
	write("002_fix.sql", `
drop policy "temp" on notes;
create table legacy (id int);
alter table legacy enable row level security;
alter table legacy disable row level security;
`)

	result, err := AuditSQLFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]TableStatus{}
	for _, tbl := range result.Tables {
		got[tbl.TableName] = tbl
	}
	check := func(name string, vulnerable bool, issues int) {
		t.Helper()
		tbl, ok := got[name]
		if !ok {
			t.Fatalf("table %s not found in %+v", name, result.Tables)
		}
		if tbl.Vulnerable() != vulnerable || len(tbl.Issues) != issues {
			t.Errorf("%s: vulnerable=%v issues=%d, want %v/%d (%+v)", name, tbl.Vulnerable(), len(tbl.Issues), vulnerable, issues, tbl.Issues)
		}
	}
	check("profiles", true, 1)   // RLS on, but open update policy
	check("posts", false, 1)     // public read is a warning only
	check("notes", false, 0)     // open policy was dropped in a later migration
	check("audit_log", false, 0) // service_role only
	check("legacy", true, 0)     // RLS disabled again
	if got["profiles"].LineNumber != 2 {
		t.Errorf("profiles should start on line 2, got %d", got["profiles"].LineNumber)
	}
	if result.TotalTables != 5 || result.VulnerableTables != 2 {
		t.Errorf("totals: %d tables, %d vulnerable", result.TotalTables, result.VulnerableTables)
	}
}
