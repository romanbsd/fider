package dbx

import (
	"context"
	"database/sql"
	stdErrors "errors"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/getfider/fider/app/models/dto"
	"github.com/getfider/fider/app/pkg/env"
	"github.com/getfider/fider/app/pkg/errors"
	"github.com/getfider/fider/app/pkg/log"
)

// ErrNoChanges means that the migration process didn't change execute any file
var ErrNoChanges = stdErrors.New("nothing to migrate")

// Migrate the database to latest version
func Migrate(ctx context.Context, path string) error {
	log.Info(ctx, "Running migrations...")
	dir, err := os.Open(env.Path(path))
	if err != nil {
		return errors.Wrap(err, "failed to open dir '%s'", path)
	}

	files, err := dir.Readdir(0)
	if err != nil {
		return errors.Wrap(err, "failed to read files from dir '%s'", path)
	}

	versions := make([]int, len(files))
	versionFiles := make(map[int]string, len(files))
	for i, file := range files {
		fileName := file.Name()
		parts := strings.Split(fileName, "_")
		if len(parts[0]) != 12 {
			return errors.New("migration file must have exactly 12 chars for version: '%s' is invalid.", fileName)
		}

		versions[i], err = strconv.Atoi(parts[0])
		versionFiles[versions[i]] = fileName
		if err != nil {
			return errors.Wrap(err, "failed to convert '%s' to number", parts[0])
		}
	}
	sort.Ints(versions)

	log.Infof(ctx, "Found total of @{Total} migration files.", dto.Props{
		"Total": len(versions),
	})

	lastVersion, err := getLastMigration()
	if err != nil {
		return errors.Wrap(err, "failed to get last migration record")
	}

	log.Infof(ctx, "Current version is @{Version}", dto.Props{
		"Version": lastVersion,
	})

	totalMigrationsExecuted := 0

	// Apply all migrations
	for _, version := range versions {
		if version > lastVersion {
			fileName := versionFiles[version]
			log.Infof(ctx, "Running Version: @{Version} (@{FileName})", dto.Props{
				"Version":  version,
				"FileName": fileName,
			})
			err := runMigration(ctx, version, path, fileName)
			if err != nil {
				return errors.Wrap(err, "failed to run migration '%s'", fileName)
			}
			totalMigrationsExecuted++
		}
	}

	if totalMigrationsExecuted > 0 {
		log.Infof(ctx, "@{Count} migrations have been applied.", dto.Props{
			"Count": totalMigrationsExecuted,
		})
	} else {
		log.Info(ctx, "Migrations are already up to date.")
	}
	return nil
}

func runMigration(ctx context.Context, version int, path, fileName string) error {
	filePath := env.Path(path + "/" + fileName)
	content, err := os.ReadFile(filePath)
	if err != nil {
		return errors.Wrap(err, "failed to read file '%s'", filePath)
	}

	sql := string(content)
	statements := splitStatements(sql)
	if isConcurrentMigration(statements) {
		// CREATE/DROP INDEX CONCURRENTLY cannot run inside a transaction (nor
		// share an implicit transaction with other statements), so each
		// CONCURRENTLY statement runs on its own, outside any transaction. Every
		// other statement of the migration is batched into a single explicit
		// transaction, keeping the DDL portion all-or-nothing. The migration as a
		// whole is still not atomic: a failure between the transactional batch
		// and a CONCURRENTLY statement leaves the batch committed and the
		// migration unrecorded. Migration files using CONCURRENTLY must therefore
		// be written idempotently (IF NOT EXISTS etc.) so the next run can
		// recover.
		commitBatch := func(trx *Trx) error {
			if trx == nil {
				return nil
			}
			if err := trx.Commit(); err != nil {
				return errors.Wrap(err, "failed to commit migration batch")
			}
			return nil
		}

		var trx *Trx
		for i, statement := range statements {
			stripped := stripLeadingComments(statement)
			if concurrentIndexRegex.MatchString(stripped) || dropConcurrentIndexRegex.MatchString(stripped) {
				// Commit the batch of ordinary statements accumulated so far:
				// the CONCURRENTLY statement must run outside it.
				if err := commitBatch(trx); err != nil {
					return errors.Wrap(err, "failed to run migration '%s'", fileName)
				}
				trx = nil

				if name, ok := dropIndexTarget(stripped); ok {
					valid, err := indexIsValid(name)
					if err != nil {
						return errors.Wrap(err, "failed to run migration '%s'", fileName)
					}
					if valid && rebuildsIndex(statements, i+1, name) {
						// This drop is the repair half of a drop-then-rebuild
						// sequence: the index is valid, so dropping it here would
						// open a window, before the CONCURRENTLY rebuild below
						// completes, where concurrent writes could violate the
						// constraint it enforces (and could then make the rebuild
						// itself fail). Only an invalid index left behind by an
						// interrupted CONCURRENTLY build, or a standalone drop
						// with nothing rebuilding the index, is executed here.
						continue
					}
				}
				if _, err := conn.Exec(statement); err != nil {
					return errors.Wrap(err, "failed to run migration '%s'", fileName)
				}
				continue
			}

			if trx == nil {
				trx, err = BeginTx(ctx)
				if err != nil {
					return errors.Wrap(err, "failed to run migration '%s'", fileName)
				}
			}
			if _, err := trx.Execute(statement); err != nil {
				_ = trx.Rollback()
				return errors.Wrap(err, "failed to run migration '%s'", fileName)
			}
		}

		if err := commitBatch(trx); err != nil {
			return errors.Wrap(err, "failed to run migration '%s'", fileName)
		}

		if _, err := conn.Exec("INSERT INTO migrations_history (version, filename) VALUES ($1, $2)", version, fileName); err != nil {
			return errors.Wrap(err, "failed to record migration '%s'", fileName)
		}
		return nil
	}

	trx, err := BeginTx(ctx)
	if err != nil {
		return err
	}

	_, err = trx.tx.Exec(sql)
	if err != nil {
		return err
	}

	_, err = trx.Execute("INSERT INTO migrations_history (version, filename) VALUES ($1, $2)", version, fileName)
	if err != nil {
		return err
	}

	return trx.Commit()
}

var concurrentIndexRegex = regexp.MustCompile(`(?i)^CREATE\s+(UNIQUE\s+)?INDEX\s+CONCURRENTLY\b`)

// dropConcurrentIndexRegex matches DROP INDEX CONCURRENTLY statements, which
// (like CREATE INDEX CONCURRENTLY) cannot run inside a transaction.
var dropConcurrentIndexRegex = regexp.MustCompile(`(?i)^DROP\s+INDEX\s+CONCURRENTLY\b`)

// identPattern matches one SQL identifier: either double-quoted (preserving
// case and any character, "" is an escaped quote) or a bare identifier.
const identPattern = `(?:"(?:[^"]|"")+"|[A-Za-z_][A-Za-z0-9_$]*)`

var dropIndexRegex = regexp.MustCompile(`(?i)^DROP\s+INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+EXISTS\s+)?(` + identPattern + `(?:\.` + identPattern + `)?)\s*;?\s*$`)

// createIndexRegex matches a CREATE INDEX statement and captures the index
// name (schema-qualified and/or quoted, exactly as written), used to tell a
// drop-then-rebuild repair sequence apart from a standalone DROP INDEX.
var createIndexRegex = regexp.MustCompile(`(?i)^CREATE\s+(UNIQUE\s+)?INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?(` + identPattern + `(?:\.` + identPattern + `)?)`)

// rebuildsIndex reports whether statements[start:] contains a CREATE INDEX for
// the given name, i.e. the migration drops then rebuilds it (the repair
// recovery sequence). Used to decide whether a DROP INDEX of an already-valid
// index is the repair half of that sequence (skip it, to avoid a window where
// concurrent writes could violate the constraint) or a standalone drop that
// the author intends to execute.
func rebuildsIndex(statements []string, start int, name string) bool {
	for _, s := range statements[start:] {
		m := createIndexRegex.FindStringSubmatch(stripLeadingComments(s))
		// group 1 is the optional "UNIQUE " token; group 2 is the index name
		if m != nil && m[2] == name {
			return true
		}
	}
	return false
}

// stripLeadingComments removes any leading line/block comments from s (as
// isConcurrentMigration does), so a keyword-anchored regex can match
// statements that a migration author chose to document.
func stripLeadingComments(s string) string {
	cleaned := strings.TrimSpace(s)
	for {
		switch {
		case strings.HasPrefix(cleaned, "--"):
			end := strings.IndexByte(cleaned, '\n')
			if end == -1 {
				return ""
			}
			cleaned = strings.TrimSpace(cleaned[end+1:])
		case strings.HasPrefix(cleaned, "/*"):
			cleaned = strings.TrimSpace(cleaned[blockCommentEnd(cleaned, 0):])
		default:
			return cleaned
		}
	}
}

// dropIndexTarget returns the exact index reference (schema-qualified and/or
// quoted, as written) targeted by a DROP INDEX statement, if the statement
// (after any leading comments) is exactly that. The reference is returned
// unmodified so it can be passed straight to to_regclass, which parses
// quoting and case-folding the same way the SQL parser does.
func dropIndexTarget(statement string) (string, bool) {
	m := dropIndexRegex.FindStringSubmatch(stripLeadingComments(statement))
	if m == nil {
		return "", false
	}
	return m[1], true
}

// indexIsValid reports whether an index with the given name currently exists
// and is valid (i.e. not left behind by an interrupted CONCURRENTLY build).
func indexIsValid(name string) (bool, error) {
	var valid bool
	row := conn.QueryRow(`SELECT indisvalid FROM pg_index WHERE indexrelid = to_regclass($1)`, name)
	if err := row.Scan(&valid); err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	return valid, nil
}

// isConcurrentMigration reports whether any statement of the script is a
// CREATE or DROP INDEX CONCURRENTLY, ignoring leading SQL comments. Detection
// runs on the split statements so the word CONCURRENTLY inside comments or
// quoted identifiers cannot trigger the non-transactional path.
func isConcurrentMigration(statements []string) bool {
	for _, s := range statements {
		s = stripLeadingComments(s)
		if concurrentIndexRegex.MatchString(s) || dropConcurrentIndexRegex.MatchString(s) {
			return true
		}
	}
	return false
}

// splitStatements splits a SQL script into individual statements, honouring
// single-quoted literals, double-quoted identifiers, dollar-quoted strings,
// and SQL comments, so statements can be run outside a transaction (e.g.
// CREATE INDEX CONCURRENTLY).
func splitStatements(script string) []string {
	var (
		statements []string
		start      int
		i          int
	)

	for i < len(script) {
		switch script[i] {
		case '\'', '"':
			quote := script[i]
			// E'...' strings (but not plain '...' literals) treat backslash as an
			// escape character, so \' there does not terminate the literal. The
			// E prefix is a standalone token: a preceding identifier character
			// means the 'e' is part of a word (e.g. ...name='a'), not an E-string.
			eString := quote == '\'' && i > 0 &&
				(script[i-1] == 'e' || script[i-1] == 'E') &&
				(i < 2 || !isIdentChar(script[i-2]))
			for {
				end := strings.IndexByte(script[i+1:], quote)
				if end == -1 {
					i = len(script)
					break
				}
				i += end + 1
				if eString && escapedEStringQuote(script, i-1) {
					// escaped quote inside an E-string literal (E'it\'s'); a quote
					// is only escaped by an odd-length run of backslashes — an
					// even run pairs them up and leaves the quote as the literal's
					// terminator
					i++
					continue
				}
				if i+1 < len(script) && script[i+1] == quote {
					// escaped quote inside the literal/identifier ('')
					i++
					continue
				}
				i++
				break
			}
		case '$':
			if tag, ok := dollarQuoteTag(script, i); ok {
				end := strings.Index(script[i+len(tag):], tag)
				if end == -1 {
					i = len(script)
				} else {
					i += len(tag) + end + len(tag)
				}
			} else {
				i++
			}
		case ';':
			statements = append(statements, strings.TrimSpace(script[start:i+1]))
			i++
			start = i
		case '-':
			if i+1 < len(script) && script[i+1] == '-' {
				if end := strings.IndexByte(script[i+2:], '\n'); end == -1 {
					i = len(script)
				} else {
					i += 2 + end + 1
				}
			} else {
				i++
			}
		case '/':
			if i+1 < len(script) && script[i+1] == '*' {
				i = blockCommentEnd(script, i)
			} else {
				i++
			}
		default:
			i++
		}
	}

	if trailing := strings.TrimSpace(script[start:]); trailing != "" {
		statements = append(statements, trailing)
	}
	return statements
}

// blockCommentEnd returns the index just past the closing "*/" for a block
// comment starting at s[start:start+2] == "/*", honouring nested block
// comments (Postgres allows /* /* */ */, unlike C). Returns len(s) if the
// comment is unterminated.
func blockCommentEnd(s string, start int) int {
	depth := 0
	i := start
	for i < len(s) {
		switch {
		case strings.HasPrefix(s[i:], "/*"):
			depth++
			i += 2
		case strings.HasPrefix(s[i:], "*/"):
			depth--
			i += 2
			if depth == 0 {
				return i
			}
		default:
			i++
		}
	}
	return len(s)
}

// isIdentChar reports whether b can appear inside a PostgreSQL identifier.
// Used to distinguish a standalone E-string prefix from an 'e' that is the last
// letter of an identifier.
func isIdentChar(b byte) bool {
	return b == '_' || b == '$' ||
		b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
}

// escapedEStringQuote reports whether the quote at index start-1 inside an
// E-string is escaped by the run of backslashes directly before it. PostgreSQL
// pairs consecutive backslashes up, so only an odd-length run escapes the
// following quote; an even-length run leaves the quote as the literal's
// terminator.
func escapedEStringQuote(script string, start int) bool {
	backslashes := 0
	for j := start; j >= 0 && script[j] == '\\'; j-- {
		backslashes++
	}
	return backslashes%2 == 1
}

func dollarQuoteTag(script string, i int) (string, bool) {
	if script[i] != '$' {
		return "", false
	}

	j := i + 1
	for j < len(script) && (script[j] == '_' || script[j] >= 'a' && script[j] <= 'z' || script[j] >= 'A' && script[j] <= 'Z' || script[j] >= '0' && script[j] <= '9') {
		if j == i+1 && script[j] >= '0' && script[j] <= '9' {
			return "", false
		}
		j++
	}
	if j >= len(script) || script[j] != '$' {
		return "", false
	}
	return script[i : j+1], true
}

func getLastMigration() (int, error) {
	_, err := conn.Exec(`CREATE TABLE IF NOT EXISTS migrations_history (
		version     BIGINT PRIMARY KEY,
		filename    VARCHAR(100) null,
		date	 			TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`)
	if err != nil {
		return 0, err
	}

	var lastVersion sql.NullInt64
	row := conn.QueryRow("SELECT MAX(version) FROM migrations_history LIMIT 1")
	err = row.Scan(&lastVersion)
	if err != nil {
		return 0, err
	}

	if !lastVersion.Valid {
		// If it's the first run, maybe we have records on old migrations table, so try to get from it.
		// This SHOULD be removed in the far future.
		row := conn.QueryRow("SELECT version FROM schema_migrations LIMIT 1")
		_ = row.Scan(&lastVersion)
	}

	return int(lastVersion.Int64), nil
}
