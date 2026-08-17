package dbx

import (
	"context"
	"database/sql"
	stdErrors "errors"
	"os"
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
	if strings.Contains(strings.ToUpper(sql), "CONCURRENTLY") {
		// CREATE INDEX CONCURRENTLY cannot run inside a transaction (nor share an
		// implicit transaction with other statements), so the statements of this
		// migration run one at a time, each in its own implicit transaction.
		for _, statement := range splitStatements(sql) {
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

// splitStatements splits a SQL script into individual statements, honouring
// single-quoted literals and dollar-quoted strings, so statements can be run
// outside a transaction (e.g. CREATE INDEX CONCURRENTLY).
func splitStatements(script string) []string {
	var (
		statements []string
		start      int
		i          int
	)

	for i < len(script) {
		switch script[i] {
		case '\'':
			for {
				end := strings.IndexByte(script[i+1:], '\'')
				if end == -1 {
					i = len(script)
					break
				}
				i += end + 1
				if i+1 < len(script) && script[i+1] == '\'' {
					// escaped quote inside the literal
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
		default:
			i++
		}
	}

	if trailing := strings.TrimSpace(script[start:]); trailing != "" {
		statements = append(statements, trailing)
	}
	return statements
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
