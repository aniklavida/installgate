package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestApprovalExpiresAndStopsBeingHonoured(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "approvals_clock.db")

	store1, err := OpenSQLite(dbPath)
	if err != nil {
		t.Fatalf("failed opening store: %v", err)
	}

	if err := store1.ApplyMigrations(ctx); err != nil {
		t.Fatalf("failed applying migrations: %v", err)
	}

	baseTime := time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC)
	expiryTime := baseTime.Add(1 * time.Hour) // Exactly 1 hour expiry

	app := &Approval{
		ID:        "app-controlled-clock-1",
		Package:   "risk-package",
		Version:   "1.2.3",
		Reason:    "approved after manual security review of install script",
		Actor:     "security-auditor-human",
		CreatedAt: baseTime,
		ExpiresAt: expiryTime,
	}

	if err := store1.CreateApproval(ctx, app); err != nil {
		t.Fatalf("failed to create approval: %v", err)
	}

	// 1. Controlled Clock Test: Before Expiry (at baseTime + 30m) -> MUST BE HONOURED
	timeBeforeExpiry := baseTime.Add(30 * time.Minute)
	foundApp, isHonoured, err := store1.FindActiveApproval(ctx, "risk-package", "1.2.3", timeBeforeExpiry)
	if err != nil {
		t.Fatalf("unexpected error finding active approval: %v", err)
	}
	if !isHonoured || foundApp == nil {
		t.Fatalf("expected approval to be active and honoured at %v, got isHonoured=%v", timeBeforeExpiry, isHonoured)
	}
	if !foundApp.IsActive(timeBeforeExpiry) {
		t.Fatalf("expected approval.IsActive to be true at %v", timeBeforeExpiry)
	}

	// 2. Controlled Clock Test: EXACT Expiry Boundary (at expiryTime) -> MUST STOP BEING HONOURED
	foundAppAtExpiry, isHonouredAtExpiry, err := store1.FindActiveApproval(ctx, "risk-package", "1.2.3", expiryTime)
	if err != nil {
		t.Fatalf("unexpected error finding approval at expiry: %v", err)
	}
	if isHonouredAtExpiry || foundAppAtExpiry != nil {
		t.Fatalf("expected approval to STOP being honoured at exactly expiry time %v, got isHonoured=%v", expiryTime, isHonouredAtExpiry)
	}
	if app.IsActive(expiryTime) {
		t.Fatalf("expected approval.IsActive to be false at expiry time %v", expiryTime)
	}

	// 3. Controlled Clock Test: After Expiry (at baseTime + 2h) -> MUST STOP BEING HONOURED
	timeAfterExpiry := baseTime.Add(2 * time.Hour)
	foundAppAfter, isHonouredAfter, err := store1.FindActiveApproval(ctx, "risk-package", "1.2.3", timeAfterExpiry)
	if err != nil {
		t.Fatalf("unexpected error finding approval after expiry: %v", err)
	}
	if isHonouredAfter || foundAppAfter != nil {
		t.Fatalf("expected approval to STOP being honoured past expiry at %v, got isHonoured=%v", timeAfterExpiry, isHonouredAfter)
	}
	if app.IsActive(timeAfterExpiry) {
		t.Fatalf("expected approval.IsActive to be false at %v", timeAfterExpiry)
	}

	// Close store1 to prove restart preserves approvals
	if err := store1.Close(); err != nil {
		t.Fatalf("failed closing store: %v", err)
	}

	// 4. Restart persistence test
	store2, err := OpenSQLite(dbPath)
	if err != nil {
		t.Fatalf("failed reopening store: %v", err)
	}
	defer store2.Close()

	// Before expiry check on restarted store
	foundRestart, isHonouredRestart, err := store2.FindActiveApproval(ctx, "risk-package", "1.2.3", timeBeforeExpiry)
	if err != nil || !isHonouredRestart || foundRestart == nil {
		t.Fatalf("approval did not survive restart: honoured=%v, err=%v", isHonouredRestart, err)
	}

	// After expiry check on restarted store
	_, isHonouredAfterRestart, err := store2.FindActiveApproval(ctx, "risk-package", "1.2.3", timeAfterExpiry)
	if err != nil || isHonouredAfterRestart {
		t.Fatalf("approval honoured after expiry on restarted store: honoured=%v, err=%v", isHonouredAfterRestart, err)
	}
}

func TestApprovalHumanOnlyAndRevocation(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "approvals_human.db")

	store, err := OpenSQLite(dbPath)
	if err != nil {
		t.Fatalf("failed opening store: %v", err)
	}
	defer store.Close()

	if err := store.ApplyMigrations(ctx); err != nil {
		t.Fatalf("failed applying migrations: %v", err)
	}

	baseTime := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)

	// Automated / agent actors MUST be rejected
	botActors := []string{"claude", "mcp-agent", "agent-runner", "bot-installer", "automated-service"}
	for _, bot := range botActors {
		badApp := &Approval{
			ID:        "bad-" + bot,
			Package:   "pkg-" + bot,
			Version:   "1.0.0",
			Reason:    "auto-approval attempt",
			Actor:     bot,
			CreatedAt: baseTime,
			ExpiresAt: baseTime.Add(time.Hour),
		}
		err := store.CreateApproval(ctx, badApp)
		if err != ErrNonHumanActor {
			t.Fatalf("expected ErrNonHumanActor for actor %q, got %v", bot, err)
		}
	}

	// Valid human approval
	validApp := &Approval{
		ID:        "human-app-1",
		Package:   "pkg-valid",
		Version:   "^1.0.0",
		Reason:    "human verified safe build",
		Actor:     "jane-developer",
		CreatedAt: baseTime,
		ExpiresAt: baseTime.Add(24 * time.Hour),
	}
	if err := store.CreateApproval(ctx, validApp); err != nil {
		t.Fatalf("failed creating valid human approval: %v", err)
	}

	// Version matching
	_, foundMatch, err := store.FindActiveApproval(ctx, "pkg-valid", "1.2.3", baseTime.Add(time.Hour))
	if err != nil || !foundMatch {
		t.Fatalf("expected ^1.0.0 to match 1.2.3, got found=%v, err=%v", foundMatch, err)
	}

	_, foundMismatch, err := store.FindActiveApproval(ctx, "pkg-valid", "2.0.0", baseTime.Add(time.Hour))
	if err != nil || foundMismatch {
		t.Fatalf("expected ^1.0.0 NOT to match 2.0.0, got found=%v, err=%v", foundMismatch, err)
	}

	// Revocation
	revokeTime := baseTime.Add(2 * time.Hour)
	if err := store.RevokeApproval(ctx, "human-app-1", revokeTime); err != nil {
		t.Fatalf("failed revoking approval: %v", err)
	}

	// After revocation, must NOT be honoured even if before expiry
	checkAfterRevoke := baseTime.Add(3 * time.Hour)
	_, activeAfterRevoke, err := store.FindActiveApproval(ctx, "pkg-valid", "1.2.3", checkAfterRevoke)
	if err != nil || activeAfterRevoke {
		t.Fatalf("expected revoked approval to not be honoured, got active=%v, err=%v", activeAfterRevoke, err)
	}
}
