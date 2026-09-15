package store

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aniklavida/installgate/internal/evidence"
	"github.com/aniklavida/installgate/internal/explanation"
	"github.com/aniklavida/installgate/internal/verdict"
)

func TestBackupRestoreAndCacheRebuildEndToEnd(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "live.db")
	backupPath := filepath.Join(dir, "live_backup.db")
	restoredPath := filepath.Join(dir, "restored.db")

	store, err := OpenSQLite(dbPath)
	if err != nil {
		t.Fatalf("failed opening sqlite store: %v", err)
	}
	defer store.Close()

	if err := store.ApplyMigrations(ctx); err != nil {
		t.Fatalf("failed applying migrations: %v", err)
	}

	// 1. Populate data across subsystems
	if err := store.RecordConfigHistory(ctx, "enable", "committed", `{"registry":"http://127.0.0.1:8765"}`); err != nil {
		t.Fatalf("failed recording config: %v", err)
	}

	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	app := &Approval{
		ID:        "app-test-1",
		Package:   "lodash",
		Version:   "4.17.21",
		Reason:    "approved for internal build tool",
		Actor:     "operator",
		CreatedAt: now,
		ExpiresAt: now.Add(24 * time.Hour),
	}
	if err := store.CreateApproval(ctx, app); err != nil {
		t.Fatalf("failed creating approval: %v", err)
	}

	doc := &explanation.DecisionDocument{
		SchemaVersion: "1",
		DecisionID:    "dec-backup-test",
		Package:       "express",
		Version:       "4.18.2",
		Verdict:       verdict.Allow,
		SnapshotID:    "snap-test-1",
		Reasons: []explanation.ReasonExplanation{
			{
				RuleID:  "reputation.established",
				Summary: "package meets baseline criteria",
			},
		},
	}
	if err := store.SaveDecision(ctx, doc); err != nil {
		t.Fatalf("failed saving decision: %v", err)
	}

	// Cache an outcome
	advOutcome := evidence.NewAvailableOutcome("advisory", "mock", nil, now, now.Add(time.Hour))
	if err := store.SaveCachedEvidence(ctx, "express", "4.18.2", "advisory", advOutcome, now.Add(2*time.Hour)); err != nil {
		t.Fatalf("failed saving cached evidence: %v", err)
	}

	// Cache an allow decision
	dec := verdict.Decision{
		Verdict: verdict.Allow,
		Reasons: []verdict.Reason{
			{
				RuleID:  "reputation.established",
				Summary: "package meets baseline criteria",
			},
		},
	}
	if err := store.SaveCachedAllow(ctx, "express", "4.18.2", dec, "snap-test-1", now, now.Add(time.Hour), now.Add(2*time.Hour)); err != nil {
		t.Fatalf("failed saving cached allow: %v", err)
	}

	// Record audit event
	auditEv := &AuditEvent{
		EventTime:  now,
		EventType:  "decision",
		Package:    "express",
		Version:    "4.18.2",
		DecisionID: "dec-backup-test",
		RuleID:     "reputation.established",
		Verdict:    "allow",
		Actor:      "gateway",
	}
	if err := store.AppendAudit(ctx, auditEv); err != nil {
		t.Fatalf("failed appending audit: %v", err)
	}

	// 2. Perform live backup
	if err := store.Backup(ctx, backupPath); err != nil {
		t.Fatalf("failed performing backup: %v", err)
	}

	if _, err := os.Stat(backupPath); err != nil {
		t.Fatalf("backup file does not exist: %v", err)
	}

	// 3. Test Cache Eviction & Rebuild on Live DB
	// Clear cache
	if err := store.ClearEvidenceCache(ctx); err != nil {
		t.Fatalf("failed clearing evidence cache: %v", err)
	}

	// Verify cache entries are absent
	_, foundEv, err := store.GetCachedEvidence(ctx, "advisory", "express", "4.18.2", now)
	if err != nil || foundEv {
		t.Fatalf("expected cached evidence to be absent after clear, found=%v (err=%v)", foundEv, err)
	}
	_, foundAllow, err := store.GetCachedAllow(ctx, "express", "4.18.2", now)
	if err != nil || foundAllow {
		t.Fatalf("expected cached allow to be absent after clear, found=%v (err=%v)", foundAllow, err)
	}

	// Rebuild Cache from preserved decision document
	rebuiltDoc, err := store.GetDecision(ctx, "dec-backup-test")
	if err != nil {
		t.Fatalf("failed getting decision for cache rebuild: %v", err)
	}
	rebuiltDec := verdict.Decision{
		Verdict: rebuiltDoc.Verdict,
		Reasons: []verdict.Reason{
			{
				RuleID:  rebuiltDoc.Reasons[0].RuleID,
				Summary: rebuiltDoc.Reasons[0].Summary,
			},
		},
	}
	if err := store.SaveCachedAllow(ctx, rebuiltDoc.Package, rebuiltDoc.Version, rebuiltDec, rebuiltDoc.SnapshotID, now, now.Add(time.Hour), now.Add(2*time.Hour)); err != nil {
		t.Fatalf("failed saving rebuilt cached allow: %v", err)
	}

	// Verify cache is successfully rebuilt
	cachedAllow, foundRebuilt, err := store.GetCachedAllow(ctx, "express", "4.18.2", now)
	if err != nil || !foundRebuilt {
		t.Fatalf("expected cached allow to be present after rebuild, found=%v (err=%v)", foundRebuilt, err)
	}
	if cachedAllow.Decision.Verdict != verdict.Allow {
		t.Fatalf("expected allow verdict, got %v", cachedAllow.Decision.Verdict)
	}

	// 4. Test Restore: copy backup file to restoredPath and open it
	backupBytes, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("failed reading backup file: %v", err)
	}
	if err := os.WriteFile(restoredPath, backupBytes, 0o600); err != nil {
		t.Fatalf("failed writing restored database file: %v", err)
	}

	restoredStore, err := OpenSQLite(restoredPath)
	if err != nil {
		t.Fatalf("failed opening restored store: %v", err)
	}
	defer restoredStore.Close()

	// Verify all restored state
	configs, err := restoredStore.ListConfigHistory(ctx, 10)
	if err != nil || len(configs) != 1 {
		t.Fatalf("expected 1 restored config record, got %d (err: %v)", len(configs), err)
	}

	restoredApp, err := restoredStore.GetApproval(ctx, "app-test-1")
	if err != nil || restoredApp.Package != "lodash" {
		t.Fatalf("failed retrieving restored approval: %v", err)
	}

	restoredDec, err := restoredStore.GetDecision(ctx, "dec-backup-test")
	if err != nil || restoredDec.Package != "express" {
		t.Fatalf("failed retrieving restored decision: %v", err)
	}

	restoredAudit, err := restoredStore.FindAuditByDecision(ctx, "dec-backup-test")
	if err != nil || restoredAudit.Package != "express" {
		t.Fatalf("failed retrieving restored audit event: %v", err)
	}
}

func TestAuditLogIsStrictlyAppendOnly(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "audit_append_only.db")

	store, err := OpenSQLite(dbPath)
	if err != nil {
		t.Fatalf("failed opening store: %v", err)
	}
	defer store.Close()

	if err := store.ApplyMigrations(ctx); err != nil {
		t.Fatalf("failed applying migrations: %v", err)
	}

	ev := &AuditEvent{
		EventTime: time.Now().UTC(),
		EventType: "lifecycle",
		Actor:     "test",
	}
	if err := store.AppendAudit(ctx, ev); err != nil {
		t.Fatalf("failed inserting initial audit event: %v", err)
	}

	// 1. Attempt database-level UPDATE -> MUST be rejected by trigger
	_, err = store.db.ExecContext(ctx, "UPDATE audit_events SET event_type = 'tampered' WHERE id = ?", ev.ID)
	if err == nil {
		t.Fatal("expected UPDATE on audit_events to be blocked by append-only trigger, got success")
	}
	if !strings.Contains(err.Error(), "append-only") && !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("unexpected error message on blocked update: %v", err)
	}

	// 2. Attempt database-level DELETE -> MUST be rejected by trigger
	_, err = store.db.ExecContext(ctx, "DELETE FROM audit_events WHERE id = ?", ev.ID)
	if err == nil {
		t.Fatal("expected DELETE on audit_events to be blocked by append-only trigger, got success")
	}
	if !strings.Contains(err.Error(), "append-only") && !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("unexpected error message on blocked delete: %v", err)
	}

	// 3. Verify event is unchanged
	reRead, err := store.GetAuditEvent(ctx, ev.ID)
	if err != nil {
		t.Fatalf("failed retrieving audit event after tampering attempts: %v", err)
	}
	if reRead.EventType != "lifecycle" {
		t.Fatalf("audit event was mutated! got event_type %q", reRead.EventType)
	}
}
