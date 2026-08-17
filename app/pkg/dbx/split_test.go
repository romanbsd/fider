package dbx

import (
	"testing"
)

func TestSplitStatements(t *testing.T) {
	script := `
CREATE TABLE foo (a text);
INSERT INTO foo VALUES ('semi;colon');
CREATE OR REPLACE FUNCTION f() RETURNS void AS $$
BEGIN
  PERFORM 1;
END;
$$ LANGUAGE plpgsql;
-- comment ; not a split
/* block comment ; not a split */
SELECT 1
`
	got := splitStatements(script)
	want := []string{
		"CREATE TABLE foo (a text);",
		"INSERT INTO foo VALUES ('semi;colon');",
		"CREATE OR REPLACE FUNCTION f() RETURNS void AS $$\nBEGIN\n  PERFORM 1;\nEND;\n$$ LANGUAGE plpgsql;",
		"-- comment ; not a split\n/* block comment ; not a split */\nSELECT 1",
	}

	if len(got) != len(want) {
		t.Fatalf("expected %d statements, got %d: %q", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("statement %d mismatch:\n got: %q\nwant: %q", i, got[i], want[i])
		}
	}
}

func TestSplitStatements_EscapedQuotes(t *testing.T) {
	script := `INSERT INTO t VALUES ('it''s; fine');
SELECT 1;`

	got := splitStatements(script)
	want := []string{
		"INSERT INTO t VALUES ('it''s; fine');",
		"SELECT 1;",
	}

	if len(got) != len(want) {
		t.Fatalf("expected %d statements, got %d: %q", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("statement %d mismatch:\n got: %q\nwant: %q", i, got[i], want[i])
		}
	}
}

func TestSplitStatements_QuotedIdentifier(t *testing.T) {
	script := `CREATE TABLE "weird;name" (a text);
SELECT 1;`

	got := splitStatements(script)
	want := []string{
		`CREATE TABLE "weird;name" (a text);`,
		"SELECT 1;",
	}

	if len(got) != len(want) {
		t.Fatalf("expected %d statements, got %d: %q", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("statement %d mismatch:\n got: %q\nwant: %q", i, got[i], want[i])
		}
	}
}

func TestSplitStatements_NestedBlockComment(t *testing.T) {
	script := `/* outer /* inner ; still commented */ still commented too */
SELECT 1;`

	got := splitStatements(script)
	want := []string{
		"/* outer /* inner ; still commented */ still commented too */\nSELECT 1;",
	}

	if len(got) != len(want) {
		t.Fatalf("expected %d statements, got %d: %q", len(want), len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("statement %d mismatch:\n got: %q\nwant: %q", i, got[i], want[i])
		}
	}
}

func TestDropIndexTarget(t *testing.T) {
	cases := []struct {
		name       string
		statement  string
		wantName   string
		wantExists bool
	}{
		{
			name:       "plain",
			statement:  "DROP INDEX foo;",
			wantName:   "foo",
			wantExists: true,
		},
		{
			name:       "if exists",
			statement:  "DROP INDEX IF EXISTS foo;",
			wantName:   "foo",
			wantExists: true,
		},
		{
			name:       "concurrently if exists",
			statement:  "DROP INDEX CONCURRENTLY IF EXISTS users_tenant_device_hash_idx;",
			wantName:   "users_tenant_device_hash_idx",
			wantExists: true,
		},
		{
			name:       "quoted name",
			statement:  `DROP INDEX IF EXISTS "foo";`,
			wantName:   "foo",
			wantExists: true,
		},
		{
			name:       "not a drop index",
			statement:  "CREATE INDEX foo ON bar (id);",
			wantExists: false,
		},
	}

	for _, tc := range cases {
		name, ok := dropIndexTarget(tc.statement)
		if ok != tc.wantExists {
			t.Errorf("%s: got ok=%v, want %v", tc.name, ok, tc.wantExists)
			continue
		}
		if ok && name != tc.wantName {
			t.Errorf("%s: got name %q, want %q", tc.name, name, tc.wantName)
		}
	}
}

func TestSplitStatements_Empty(t *testing.T) {
	got := splitStatements("  \n\t ")
	if len(got) != 0 {
		t.Fatalf("expected no statements, got %q", got)
	}
}

func TestIsConcurrentMigration(t *testing.T) {
	cases := []struct {
		name       string
		statements []string
		want       bool
	}{
		{
			name:       "plain create index",
			statements: splitStatements("CREATE INDEX foo ON bar (id);"),
			want:       false,
		},
		{
			name:       "concurrent unique index",
			statements: splitStatements("CREATE UNIQUE INDEX CONCURRENTLY foo ON bar (id);"),
			want:       true,
		},
		{
			name:       "concurrent index lower case",
			statements: splitStatements("create index concurrently foo on bar (id);"),
			want:       true,
		},
		{
			name:       "word in a comment is ignored",
			statements: splitStatements("-- concurrent index here\nCREATE TABLE foo (id int);"),
			want:       false,
		},
		{
			name:       "word in a comment lines up with real migration",
			statements: splitStatements("-- blabla CONCURRENTLY blabla\nCREATE UNIQUE INDEX CONCURRENTLY foo ON bar (id);"),
			want:       true,
		},
		{
			name:       "block comment before concurrent migration",
			statements: splitStatements("/* CONCURRENTLY in a comment */ CREATE INDEX CONCURRENTLY foo ON bar (id);"),
			want:       true,
		},
		{
			name:       "concurrently only inside nested comment is ignored",
			statements: splitStatements("/* outer /* CONCURRENTLY nested */ still a comment */ CREATE INDEX foo ON bar (id);"),
			want:       false,
		},
	}

	for _, tc := range cases {
		if got := isConcurrentMigration(tc.statements); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}
