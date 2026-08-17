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

func TestSplitStatements_EStringBackslashEscapes(t *testing.T) {
	script := `INSERT INTO t VALUES (E'it\'s; fine');
SELECT 1;`

	got := splitStatements(script)
	want := []string{
		`INSERT INTO t VALUES (E'it\'s; fine');`,
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

func TestSplitStatements_PlainLiteralBackslashIsNotEscape(t *testing.T) {
	// In standard-conforming strings a backslash is not an escape, so '\'' ends
	// the literal right after the backslash; the splitter must not treat the
	// quote as escaped and skip the terminating semicolon.
	script := "INSERT INTO t VALUES ('a\\'; 1);\nSELECT 2;"

	got := splitStatements(script)
	want := []string{
		"INSERT INTO t VALUES ('a\\';",
		"1);",
		"SELECT 2;",
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

func TestSplitStatements_IdentifierEndingInEIsNotEString(t *testing.T) {
	// A quote directly after a word ending in 'e' (here: 'case') is a plain
	// literal, not an E-string: the 'e' belongs to the identifier. Without the
	// guard the backslash-quote would be treated as an escape and the semicolon
	// inside the literal would never split the statement.
	script := "INSERT INTO t VALUES (case'a\\'; 1);\nSELECT 2;"

	got := splitStatements(script)
	want := []string{
		"INSERT INTO t VALUES (case'a\\';",
		"1);",
		"SELECT 2;",
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

func TestSplitStatements_EStringBackslashRunParity(t *testing.T) {
	cases := []struct {
		name   string
		script string
		want   []string
	}{
		{
			// Two backslashes pair up, so the quote is NOT escaped and closes
			// the literal; the following semicolon must split.
			name:   "even run leaves quote as terminator",
			script: "INSERT INTO t VALUES (E'a\\\\b'; SELECT 1);\nSELECT 2;",
			want: []string{
				"INSERT INTO t VALUES (E'a\\\\b';",
				"SELECT 1);",
				"SELECT 2;",
			},
		},
		{
			// Three backslashes: the third escapes the quote, so the literal
			// continues past it and the semicolon after 'b' stays part of the
			// string — only the semicolon after the real closing quote splits.
			name:   "odd run escapes quote",
			script: "INSERT INTO t VALUES (E'a\\\\\\'b; c'; SELECT 1);\nSELECT 2;",
			want: []string{
				"INSERT INTO t VALUES (E'a\\\\\\'b; c';",
				"SELECT 1);",
				"SELECT 2;",
			},
		},
	}

	for _, tc := range cases {
		got := splitStatements(tc.script)
		if len(got) != len(tc.want) {
			t.Fatalf("%s: expected %d statements, got %d: %q", tc.name, len(tc.want), len(got), got)
		}
		for i := range tc.want {
			if got[i] != tc.want[i] {
				t.Errorf("%s: statement %d mismatch:\n got: %q\nwant: %q", tc.name, i, got[i], tc.want[i])
			}
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
			name:       "quoted name preserves quoting and case",
			statement:  `DROP INDEX IF EXISTS "MyIndex";`,
			wantName:   `"MyIndex"`,
			wantExists: true,
		},
		{
			name:       "schema-qualified name",
			statement:  "DROP INDEX IF EXISTS public.foo;",
			wantName:   "public.foo",
			wantExists: true,
		},
		{
			name:       "quoted schema-qualified name",
			statement:  `DROP INDEX IF EXISTS "MySchema"."MyIndex";`,
			wantName:   `"MySchema"."MyIndex"`,
			wantExists: true,
		},
		{
			name:       "leading line comment",
			statement:  "-- repair an interrupted CONCURRENTLY build\nDROP INDEX CONCURRENTLY IF EXISTS foo;",
			wantName:   "foo",
			wantExists: true,
		},
		{
			name:       "leading multi-line comment block",
			statement:  "-- line one\n-- line two\nDROP INDEX IF EXISTS foo;",
			wantName:   "foo",
			wantExists: true,
		},
		{
			name:       "leading block comment",
			statement:  "/* repair note */\nDROP INDEX IF EXISTS foo;",
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
		{
			name:       "concurrent drop index",
			statements: splitStatements("DROP INDEX CONCURRENTLY foo;"),
			want:       true,
		},
		{
			name:       "concurrent drop with if exists",
			statements: splitStatements("DROP INDEX CONCURRENTLY IF EXISTS foo;"),
			want:       true,
		},
		{
			name:       "comment before concurrent drop",
			statements: splitStatements("-- remove an unused index\nDROP INDEX CONCURRENTLY IF EXISTS foo;"),
			want:       true,
		},
		{
			name:       "plain drop index is not concurrent",
			statements: splitStatements("DROP INDEX IF EXISTS foo;"),
			want:       false,
		},
	}

	for _, tc := range cases {
		if got := isConcurrentMigration(tc.statements); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}
