package dbx_test

import (
	"context"
	"testing"

	. "github.com/getfider/fider/app/pkg/assert"
	"github.com/getfider/fider/app/pkg/dbx"
)

func setupMigrationTest(t *testing.T) {
	RegisterT(t)
	ctx := context.Background()

	trx, _ := dbx.BeginTx(ctx)
	_, _ = trx.Execute("DELETE FROM migrations_history WHERE version >= 210001010000")
	_, _ = trx.Execute("DROP TABLE IF EXISTS dummy")
	_, _ = trx.Execute("DROP TABLE IF EXISTS foo")
	_, _ = trx.Execute("DROP TABLE IF EXISTS conc_dummy")
	_, _ = trx.Execute("DROP TABLE IF EXISTS conc_repair_dummy")
	trx.MustCommit()
}

func TestMigrate_Success(t *testing.T) {
	setupMigrationTest(t)
	ctx := context.Background()

	err := dbx.Migrate(ctx, "/app/pkg/dbx/testdata/migration_success")
	Expect(err).IsNil()

	trx, _ := dbx.BeginTx(ctx)
	var value string
	err = trx.Scalar(&value, "SELECT description FROM dummy WHERE id = 200 LIMIT 1")
	Expect(err).IsNil()
	Expect(value).Equals("Description 200Y")

	var count int
	err = trx.Scalar(&count, "SELECT COUNT(*) FROM dummy")
	Expect(err).IsNil()
	Expect(count).Equals(2)
	trx.MustRollback()
}

func TestMigrate_Failure(t *testing.T) {
	setupMigrationTest(t)
	ctx := context.Background()

	trx, _ := dbx.BeginTx(ctx)
	defer trx.MustRollback()

	err := dbx.Migrate(context.Background(), "/app/pkg/dbx/testdata/migration_failure")
	Expect(err).IsNotNil()

	_, err = trx.Execute("SELECT description FROM dummy")
	Expect(err).IsNotNil()
}

func TestMigrate_ConcurrentIndex(t *testing.T) {
	setupMigrationTest(t)
	ctx := context.Background()

	err := dbx.Migrate(ctx, "/app/pkg/dbx/testdata/migration_concurrent")
	Expect(err).IsNil()

	trx, _ := dbx.BeginTx(ctx)
	defer trx.MustRollback()

	var count int
	err = trx.Scalar(&count, `
		SELECT COUNT(*) FROM pg_indexes
		WHERE tablename = 'conc_dummy' AND indexname = 'conc_dummy_tenant_device_idx'`)
	Expect(err).IsNil()
	Expect(count).Equals(1)
}

// TestMigrate_ConcurrentIndex_RepairsInvalidIndex verifies the retry-safe
// policy used by CONCURRENTLY migrations (e.g.
// migrations/202608171200_add_widget_tokens.sql): a build interrupted by a
// constraint violation leaves an invalid index behind, and DROP INDEX IF
// EXISTS before CREATE ... CONCURRENTLY IF NOT EXISTS repairs it on the next
// run. Without the DROP, IF NOT EXISTS alone would see the invalid index by
// name and skip rebuilding it forever.
func TestMigrate_ConcurrentIndex_RepairsInvalidIndex(t *testing.T) {
	setupMigrationTest(t)
	ctx := context.Background()

	conn := dbx.Connection()

	trx, _ := dbx.BeginTx(ctx)
	_, err := trx.Execute(`CREATE TABLE conc_repair_dummy (id BIGSERIAL PRIMARY KEY, tenant_id INT NOT NULL, device_hash TEXT)`)
	Expect(err).IsNil()
	_, err = trx.Execute(`INSERT INTO conc_repair_dummy (tenant_id, device_hash) VALUES (1, 'dup'), (1, 'dup')`)
	Expect(err).IsNil()
	trx.MustCommit()

	// Simulate an interrupted concurrent build: duplicate data violates the
	// unique constraint, so Postgres leaves an invalid index behind instead
	// of no index at all.
	_, err = conn.Exec("CREATE UNIQUE INDEX CONCURRENTLY conc_repair_dummy_idx ON conc_repair_dummy (tenant_id, device_hash)")
	Expect(err).IsNotNil()

	trx, _ = dbx.BeginTx(ctx)
	var indisvalid bool
	err = trx.Scalar(&indisvalid, `SELECT indisvalid FROM pg_index WHERE indexrelid = 'conc_repair_dummy_idx'::regclass`)
	Expect(err).IsNil()
	Expect(indisvalid).IsFalse()
	trx.MustRollback()

	// Fix the underlying conflict, then repair using the same two-statement
	// policy the real migration uses.
	trx, _ = dbx.BeginTx(ctx)
	_, err = trx.Execute(`DELETE FROM conc_repair_dummy WHERE device_hash = 'dup' AND id NOT IN (SELECT MIN(id) FROM conc_repair_dummy WHERE device_hash = 'dup')`)
	Expect(err).IsNil()
	trx.MustCommit()

	_, err = conn.Exec("DROP INDEX IF EXISTS conc_repair_dummy_idx")
	Expect(err).IsNil()
	_, err = conn.Exec("CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS conc_repair_dummy_idx ON conc_repair_dummy (tenant_id, device_hash)")
	Expect(err).IsNil()

	trx, _ = dbx.BeginTx(ctx)
	defer trx.MustRollback()
	err = trx.Scalar(&indisvalid, `SELECT indisvalid FROM pg_index WHERE indexrelid = 'conc_repair_dummy_idx'::regclass`)
	Expect(err).IsNil()
	Expect(indisvalid).IsTrue()
}

// TestMigrate_ConcurrentIndex_SkipsValidIndexDrop verifies the migration
// runner does not drop an already-valid index just because the migration
// file contains a DROP INDEX statement for it: dropping a valid index right
// before a CONCURRENTLY rebuild would open a window where concurrent writes
// could violate the constraint it enforces. The index's OID staying the same
// proves it was never dropped (a drop+recreate would produce a new OID).
func TestMigrate_ConcurrentIndex_SkipsValidIndexDrop(t *testing.T) {
	setupMigrationTest(t)
	ctx := context.Background()

	conn := dbx.Connection()

	trx, _ := dbx.BeginTx(ctx)
	_, err := trx.Execute(`CREATE TABLE conc_repair_dummy (id BIGSERIAL PRIMARY KEY, tenant_id INT NOT NULL, device_hash TEXT)`)
	Expect(err).IsNil()
	trx.MustCommit()

	_, err = conn.Exec("CREATE UNIQUE INDEX CONCURRENTLY conc_repair_dummy_idx ON conc_repair_dummy (tenant_id, device_hash)")
	Expect(err).IsNil()

	trx, _ = dbx.BeginTx(ctx)
	var oidBefore string
	err = trx.Scalar(&oidBefore, `SELECT indexrelid::text FROM pg_index WHERE indexrelid = 'conc_repair_dummy_idx'::regclass`)
	Expect(err).IsNil()
	trx.MustRollback()

	err = dbx.Migrate(ctx, "/app/pkg/dbx/testdata/migration_concurrent_repair")
	Expect(err).IsNil()

	trx, _ = dbx.BeginTx(ctx)
	defer trx.MustRollback()
	var oidAfter string
	err = trx.Scalar(&oidAfter, `SELECT indexrelid::text FROM pg_index WHERE indexrelid = 'conc_repair_dummy_idx'::regclass`)
	Expect(err).IsNil()
	Expect(oidAfter).Equals(oidBefore)

	var indisvalid bool
	err = trx.Scalar(&indisvalid, `SELECT indisvalid FROM pg_index WHERE indexrelid = 'conc_repair_dummy_idx'::regclass`)
	Expect(err).IsNil()
	Expect(indisvalid).IsTrue()
}
