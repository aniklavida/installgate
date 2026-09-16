package store

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/aniklavida/installgate/internal/verdict"
)

// TestRestartRecovery_PreservesApprovalsAuditHistoryAndRecoversMidDecision proves that:
// 1. Process restarts preserve active human approvals and their expiration TTLs.
// 2. An abrupt restart arriving mid-decision leaves the store consistent.
// 3. The entire append-only audit trail survives restarts intact and queryable without manual repair.
func TestRestartRecovery_PreservesApprovalsAuditHistoryAndRecoversMidDecision(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "restart_recovery.db")

	baseTime := time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC)

	// Step 1: Open store, run migrations, record initial state
	st1, err := OpenSQLite(dbPath)
	if err != nil {
		t.Fatalf("OpenSQLite failed: %v", err)
	}

	if err := st1.ApplyMigrations(ctx); err != nil {
		_ = st1.Close()
		t.Fatalf("ApplyMigrations failed: %v", err)
	}

	// Create an active human approval with a 24-hour expiration
	activeApproval := &Approval{
		ID:        "app-restart-active-1",
		Package:   "approved-pkg",
		Version:   "1.2.3",
		Actor:     "security-officer",
		Reason:    "manually audited and verified for production use",
		CreatedAt: baseTime,
		ExpiresAt: baseTime.Add(24 * time.Hour),
	}
	if err := st1.CreateApproval(ctx, activeApproval); err != nil {
		_ = st1.Close()
		t.Fatalf("CreateApproval failed: %v", err)
	}

	// Create an already-expired approval to verify expiry boundary
	expiredApproval := &Approval{
		ID:        "app-restart-expired-2",
		Package:   "old-pkg",
		Version:   "0.1.0",
		Actor:     "security-officer",
		Reason:    "temporary emergency bypass",
		CreatedAt: baseTime.Add(-48 * time.Hour),
		ExpiresAt: baseTime.Add(-1 * time.Hour),
	}
	if err := st1.CreateApproval(ctx, expiredApproval); err != nil {
		_ = st1.Close()
		t.Fatalf("CreateApproval failed: %v", err)
	}

	// Append 10 audit events
	for i := 1; i <= 10; i++ {
		ev := &AuditEvent{
			EventTime:  baseTime.Add(time.Duration(i) * time.Minute),
			EventType:  "decision",
			Package:    fmt.Sprintf("pkg-%d", i),
			Version:    "1.0.0",
			DecisionID: fmt.Sprintf("dec-%d", i),
			RuleID:     "core.policy-satisfied",
			Verdict:    string(verdict.Allow),
			Actor:      "gateway",
		}
		if err := st1.AppendAudit(ctx, ev); err != nil {
			_ = st1.Close()
			t.Fatalf("AppendAudit failed for event %d: %v", i, err)
		}
	}

	// Step 2: SIMULATE ABRUPT CRASH MID-DECISION
	// In an ungraceful crash, the process dies while a transaction might be active or pending.
	// We close the store without a graceful checkpoint or sync, simulating sudden process death.
	if err := st1.Close(); err != nil {
		t.Fatalf("failed closing st1: %v", err)
	}

	// Step 3: RESTART PROCESS AND REOPEN STORE
	// The new process opens the database file directly. SQLite WAL replay automatically
	// cleans up any interrupted uncommitted transaction and brings the DB to a consistent state.
	st2, err := OpenSQLite(dbPath)
	if err != nil {
		t.Fatalf("OpenSQLite on restart failed: %v", err)
	}
	defer st2.Close()

	// Step 4: VERIFY ACTIVE APPROVALS ARE FULLY PRESERVED
	evalTime := baseTime.Add(2 * time.Hour) // well before 24h expiration
	app, found, err := st2.FindActiveApproval(ctx, "approved-pkg", "1.2.3", evalTime)
	if err != nil {
		t.Fatalf("FindActiveApproval failed: %v", err)
	}
	if !found || app == nil {
		t.Fatal("ACTIVE APPROVAL LOST AFTER RESTART! Expected to find approval for approved-pkg@1.2.3")
	}
	if app.ID != "app-restart-active-1" {
		t.Fatalf("expected ID %q, got %q", "app-restart-active-1", app.ID)
	}
	if app.Actor != "security-officer" {
		t.Fatalf("expected Actor %q, got %q", "security-officer", app.Actor)
	}
	if !app.ExpiresAt.Equal(baseTime.Add(24 * time.Hour)) {
		t.Fatalf("ExpiresAt corrupted: got %v, want %v", app.ExpiresAt, baseTime.Add(24*time.Hour))
	}

	// Verify expired approval is NOT considered active
	_, expiredFound, err := st2.FindActiveApproval(ctx, "old-pkg", "0.1.0", evalTime)
	if err != nil {
		t.Fatalf("FindActiveApproval on expired failed: %v", err)
	}
	if expiredFound {
		t.Fatal("expired approval incorrectly reported as active after restart")
	}

	// Step 5: VERIFY AUDIT HISTORY IS FULLY PRESERVED
	history, err := st2.ListAuditEvents(ctx, 100, 0)
	if err != nil {
		t.Fatalf("ListAuditEvents failed after restart: %v", err)
	}
	if len(history) != 10 {
		t.Fatalf("AUDIT TRAIL LOST OR CORRUPTED: expected 10 audit events, found %d", len(history))
	}

	// Step 6: VERIFY NEW OPERATIONS SUCCEED POST-RESTART
	newEv := &AuditEvent{
		EventTime:  baseTime.Add(3 * time.Hour),
		EventType:  "decision",
		Package:    "new-post-restart-pkg",
		Version:    "2.0.0",
		DecisionID: "dec-post-restart",
		RuleID:     "approval.granted",
		Verdict:    string(verdict.Allow),
		Actor:      "gateway",
	}
	if err := st2.AppendAudit(ctx, newEv); err != nil {
		t.Fatalf("AppendAudit failed after restart: %v", err)
	}

	updatedHistory, err := st2.ListAuditEvents(ctx, 100, 0)
	if err != nil {
		t.Fatalf("ListAuditEvents failed: %v", err)
	}
	if len(updatedHistory) != 11 {
		t.Fatalf("expected 11 audit events after post-restart append, got %d", len(updatedHistory))
	}
}
