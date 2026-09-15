package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
)

func TestMigrationsApplyInOrderFreshAndExisting(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "fresh.db")

	store, err := OpenSQLite(dbPath)
	if err != nil {
		t.Fatalf("failed to open fresh sqlite db: %v", err)
	}
	defer store.Close()

	// Fresh DB version must be 0
	ver, err := store.CurrentSchemaVersion(ctx)
	if err != nil {
		t.Fatalf("failed to get schema version on fresh db: %v", err)
	}
	if ver != 0 {
		t.Fatalf("expected version 0 on fresh db, got %d", ver)
	}

	// Apply migrations
	if err := store.ApplyMigrations(ctx); err != nil {
		t.Fatalf("failed applying migrations on fresh db: %v", err)
	}

	// Target version is latest migration (2)
	ver, err = store.CurrentSchemaVersion(ctx)
	if err != nil {
		t.Fatalf("failed to get schema version after migrations: %v", err)
	}
	if ver != 2 {
		t.Fatalf("expected version 2 after migrations, got %d", ver)
	}

	// Re-applying on existing DB must be a safe, idempotent no-op
	if err := store.ApplyMigrations(ctx); err != nil {
		t.Fatalf("failed applying migrations on existing db: %v", err)
	}

	ver, err = store.CurrentSchemaVersion(ctx)
	if err != nil {
		t.Fatalf("failed to get schema version on second run: %v", err)
	}
	if ver != 2 {
		t.Fatalf("expected version 2 to remain unchanged, got %d", ver)
	}
}

func TestCrashMidMigrationRecoversWithoutManualRepair(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "crash_test.db")

	// Custom hook to simulate an abrupt crash between DDL execution and migration version record insertion
	interrupted := false
	crashHook := func(version int, tx *sql.Tx) error {
		if version == 2 && !interrupted {
			interrupted = true
			// Abruptly rollback/abort the transaction to simulate process termination
			_ = tx.Rollback()
			return errors.New("simulated crash: interrupted between DDL and version record")
		}
		return nil
	}

	// 1. Open database with hook configured
	store1, err := OpenSQLite(dbPath, WithMidMigrationHook(crashHook))
	if err != nil {
		t.Fatalf("failed to open store: %v", err)
	}

	// 2. Attempt migrations: migration 1 will succeed, migration 2 will crash mid-flight
	err = store1.ApplyMigrations(ctx)
	if err == nil {
		_ = store1.Close()
		t.Fatal("expected migration to fail due to simulated mid-flight crash, got nil")
	}

	// Explicitly close the interrupted store handle to simulate process restart
	if err := store1.Close(); err != nil {
		t.Fatalf("failed closing interrupted store: %v", err)
	}

	// 3. Reopen the database from disk with a clean store (no crash hook)
	store2, err := OpenSQLite(dbPath)
	if err != nil {
		t.Fatalf("failed to reopen database after crash: %v", err)
	}
	defer store2.Close()

	// Check schema version: migration 2 was aborted before version insertion, so version must be 1
	ver, err := store2.CurrentSchemaVersion(ctx)
	if err != nil {
		t.Fatalf("failed reading schema version after crash: %v", err)
	}
	if ver != 1 {
		t.Fatalf("expected version 1 after mid-flight crash of migration 2, got %d", ver)
	}

	// 4. Recover: ApplyMigrations must cleanly complete without any manual repair
	if err := store2.ApplyMigrations(ctx); err != nil {
		t.Fatalf("recovery failed: ApplyMigrations returned error: %v", err)
	}

	ver, err = store2.CurrentSchemaVersion(ctx)
	if err != nil {
		t.Fatalf("failed reading schema version after recovery: %v", err)
	}
	if ver != 2 {
		t.Fatalf("expected version 2 after successful recovery, got %d", ver)
	}

	// 5. Verify database integrity and functionality
	if err := store2.RecordConfigHistory(ctx, "enable", "committed", "{}"); err != nil {
		t.Fatalf("failed writing to database after recovery: %v", err)
	}
	records, err := store2.ListConfigHistory(ctx, 10)
	if err != nil || len(records) != 1 {
		t.Fatalf("expected 1 config record after recovery, got %d (err: %v)", len(records), err)
	}
}
