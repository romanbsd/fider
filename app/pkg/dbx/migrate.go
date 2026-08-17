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
		// CREATE INDEX CONCURRENTLY cannot run inside a transaction (nor share an
		// implicit transaction with other statements), so the statements of this
		// migration run one at a time, each in its own implicit transaction. The
		// migration is therefore not atomic: a failed run may leave earlier
		// statements committed and unrecorded. Migration files using CONCURRENTLY
		// should be written idempotently (IF NOT EXISTS etc.) so the next run can
		// recover.
		for _, statement := range statements {
			if name, ok := dropIndexTarget(statement); ok {
				valid, err := indexIsValid(name)
				if err != nil {
					return errors.Wrap(err, "failed to run migration '%s'", fileName)
				}
				if valid {
					// A valid index doesn't need repairing: dropping it here
					// would open a window, before the CONCURRENTLY rebuild
					// below completes, where concurrent writes could violate
					// the constraint it enforces (and could then make the
					// rebuild itself fail). Only an invalid index left behind
					// by an interrupted CONCURRENTLY build needs dropping.
					continue
				}
			}
			if _, err := conn.Exec(statement); err != nil {
				return errors.Wrap(err, "failed to run migration '%s'", fileName)
			}
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

// identPattern matches one SQL identifier: either double-quoted (preserving
// case and any character, "" is an escaped quote) or a bare identifier.
const identPattern = `(?:"(?:[^"]|"")+"|[A-Za-z_][A-Za-z0-9_$]*)`

var dropIndexRegex = regexp.MustCompile(`(?i)^DROP\s+INDEX\s+(?:CONCURRENTLY\s+)?(?:IF\s+EXISTS\s+)?(` + identPattern + `(?:\.` + identPattern + `)?)\s*;?\s*$`)

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
// CREATE INDEX CONCURRENTLY, ignoring leading SQL comments. Detection runs on
// the split statements so the word CONCURRENTLY inside comments or quoted
// identifiers cannot trigger the non-transactional path.
func isConcurrentMigration(statements []string) bool {
	for _, s := range statements {
		if concurrentIndexRegex.MatchString(stripLeadingComments(s)) {
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
			for {
				end := strings.IndexByte(script[i+1:], quote)
				if end == -1 {
					i = len(script)
					break
				}
				i += end + 1
				if i+1 < len(script) && script[i+1] == quote {
					// escaped quote inside the literal/identifier
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
