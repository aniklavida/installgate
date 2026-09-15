package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Migration represents a single ordered schema migration.
type Migration struct {
	Version int
	Name    string
	Up      func(ctx context.Context, tx *sql.Tx) error
}

// MidMigrationHook is an optional test hook called between migration DDL execution
// and the schema_migrations record insertion.
type MidMigrationHook func(version int, tx *sql.Tx) error

var migrations = []Migration{
	{
		Version: 1,
		Name:    "initial_schema",
		Up: func(ctx context.Context, tx *sql.Tx) error {
			ddls := []string{
				`CREATE TABLE IF NOT EXISTS config_history (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					action TEXT NOT NULL,
					phase TEXT NOT NULL,
					payload TEXT NOT NULL,
					created_at TIMESTAMP NOT NULL
				);`,
				`CREATE TABLE IF NOT EXISTS evidence_cache (
					kind TEXT NOT NULL,
					package TEXT NOT NULL,
					version TEXT NOT NULL,
					outcome_json TEXT NOT NULL,
					retrieved_at TIMESTAMP NOT NULL,
					fresh_until TIMESTAMP NOT NULL,
					stale_until TIMESTAMP NOT NULL,
					PRIMARY KEY (kind, package, version)
				);`,
				`CREATE TABLE IF NOT EXISTS cached_allows (
					package TEXT NOT NULL,
					version TEXT NOT NULL,
					decision_json TEXT NOT NULL,
					snapshot_id TEXT NOT NULL,
					retrieved_at TIMESTAMP NOT NULL,
					fresh_until TIMESTAMP NOT NULL,
					stale_until TIMESTAMP NOT NULL,
					PRIMARY KEY (package, version)
				);`,
				`CREATE TABLE IF NOT EXISTS decisions (
					decision_id TEXT PRIMARY KEY,
					package TEXT NOT NULL,
					version TEXT NOT NULL,
					verdict TEXT NOT NULL,
					reason TEXT NOT NULL,
					rule_id TEXT NOT NULL,
					document_json TEXT NOT NULL,
					created_at TIMESTAMP NOT NULL
				);`,
				`CREATE TABLE IF NOT EXISTS approvals (
					id TEXT PRIMARY KEY,
					package TEXT NOT NULL,
					version TEXT NOT NULL,
					reason TEXT NOT NULL,
					actor TEXT NOT NULL,
					created_at TIMESTAMP NOT NULL,
					expires_at TIMESTAMP NOT NULL,
					revoked_at TIMESTAMP
				);`,
				`CREATE TABLE IF NOT EXISTS audit_events (
					id INTEGER PRIMARY KEY AUTOINCREMENT,
					event_time TIMESTAMP NOT NULL,
					event_type TEXT NOT NULL,
					package TEXT,
					version TEXT,
					decision_id TEXT,
					rule_id TEXT,
					verdict TEXT,
					actor TEXT,
					metadata_json TEXT,
					snapshot_json TEXT
				);`,
				`CREATE TRIGGER IF NOT EXISTS trg_audit_no_update
				BEFORE UPDATE ON audit_events
				BEGIN
					SELECT RAISE(ABORT, 'audit log is append-only: modifications are forbidden');
				END;`,
				`CREATE TRIGGER IF NOT EXISTS trg_audit_no_delete
				BEFORE DELETE ON audit_events
				BEGIN
					SELECT RAISE(ABORT, 'audit log is append-only: deletions are forbidden');
				END;`,
			}
			for _, stmt := range ddls {
				if _, err := tx.ExecContext(ctx, stmt); err != nil {
					return fmt.Errorf("failed executing migration 1 ddl: %w", err)
				}
			}
			return nil
		},
	},
	{
		Version: 2,
		Name:    "performance_indexes",
		Up: func(ctx context.Context, tx *sql.Tx) error {
			ddls := []string{
				`CREATE INDEX IF NOT EXISTS idx_audit_decision ON audit_events(decision_id);`,
				`CREATE INDEX IF NOT EXISTS idx_audit_package ON audit_events(package, version);`,
				`CREATE INDEX IF NOT EXISTS idx_approvals_pkg ON approvals(package, expires_at);`,
				`CREATE INDEX IF NOT EXISTS idx_decisions_pkg ON decisions(package, version);`,
			}
			for _, stmt := range ddls {
				if _, err := tx.ExecContext(ctx, stmt); err != nil {
					return fmt.Errorf("failed executing migration 2 ddl: %w", err)
				}
			}
			return nil
		},
	},
}

func initMigrationTable(ctx context.Context, db *sql.DB) error {
	const ddl = `CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY,
		name TEXT NOT NULL,
		applied_at TIMESTAMP NOT NULL
	);`
	_, err := db.ExecContext(ctx, ddl)
	if err != nil {
		return fmt.Errorf("failed to initialize schema_migrations table: %w", err)
	}
	return nil
}

func getAppliedVersions(ctx context.Context, db *sql.DB) (map[int]bool, error) {
	applied := make(map[int]bool)
	rows, err := db.QueryContext(ctx, "SELECT version FROM schema_migrations ORDER BY version ASC")
	if err != nil {
		return nil, fmt.Errorf("failed querying schema_migrations: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("failed scanning migration row: %w", err)
		}
		applied[v] = true
	}
	return applied, rows.Err()
}

func applyMigration(ctx context.Context, db *sql.DB, m Migration, hook MidMigrationHook) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed starting migration transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	// 1. Execute migration DDL
	if err := m.Up(ctx, tx); err != nil {
		return fmt.Errorf("migration %d (%s) failed: %w", m.Version, m.Name, err)
	}

	// Optional crash/interruption test hook
	if hook != nil {
		if err := hook(m.Version, tx); err != nil {
			return err
		}
	}

	// 2. Insert migration record in the exact same transaction
	const insertSQL = "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)"
	if _, err := tx.ExecContext(ctx, insertSQL, m.Version, m.Name, time.Now().UTC()); err != nil {
		return fmt.Errorf("failed recording migration %d: %w", m.Version, err)
	}

	// 3. Commit transaction atomically
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed committing migration %d: %w", m.Version, err)
	}

	return nil
}
