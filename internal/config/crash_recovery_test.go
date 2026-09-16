package config

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestCrashRecovery_InterruptedEnableRestoresPriorConfigurationByteForByte proves that
// an enable operation interrupted mid-transaction (e.g. process killed after staging but before commit)
// recovers automatically without manual repair and restores the exact prior registry configuration byte-for-byte.
func TestCrashRecovery_InterruptedEnableRestoresPriorConfigurationByteForByte(t *testing.T) {
	tempDir := t.TempDir()
	dataDir := filepath.Join(tempDir, "data")
	npmrcPath := filepath.Join(tempDir, ".npmrc")

	originalContent := []byte("registry=https://registry.npmjs.org/\nemail=user@example.com\nstrict-ssl=true\n")
	if err := os.WriteFile(npmrcPath, originalContent, 0o644); err != nil {
		t.Fatalf("failed setting up original .npmrc: %v", err)
	}

	stateStore, err := NewFileStateStore(dataDir)
	if err != nil {
		t.Fatalf("NewFileStateStore failed: %v", err)
	}

	prior := PriorConfig{
		FileExisted: true,
		RawContent:  originalContent,
	}

	// 1. Begin transaction and stage changes
	tx, err := BeginTransaction(stateStore, ActionEnable, npmrcPath, "http://127.0.0.1:8765", prior)
	if err != nil {
		t.Fatalf("BeginTransaction failed: %v", err)
	}

	newContent := []byte("registry=http://127.0.0.1:8765\n//127.0.0.1:8765/:_authToken=dummy\n")
	stagedFile, err := StageTransaction(stateStore, tx, newContent)
	if err != nil {
		t.Fatalf("StageTransaction failed: %v", err)
	}

	// Verify staged file exists
	if _, err := os.Stat(stagedFile); err != nil {
		t.Fatalf("expected staged file to exist: %v", err)
	}

	// 2. CRASH SIMULATION: Process terminates abruptly while transaction is staged (journal holds uncommitted tx)
	// (Simulate restart with fresh lifecycle manager / recovery procedure)

	freshStore, err := NewFileStateStore(dataDir)
	if err != nil {
		t.Fatalf("reopening StateStore failed: %v", err)
	}

	// 3. RECOVERY: RecoverJournal runs on startup without manual repair
	res, err := RecoverJournal(freshStore)
	if err != nil {
		t.Fatalf("RecoverJournal failed: %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil RecoveryResult")
	}
	if res.Status != "rolled_back" {
		t.Fatalf("expected status 'rolled_back', got %q", res.Status)
	}

	// 4. VERIFY: Staged file was deleted during recovery
	if _, err := os.Stat(stagedFile); !os.IsNotExist(err) {
		t.Fatalf("expected staged file %s to be deleted during recovery", stagedFile)
	}

	// 5. VERIFY: Target file matches exact prior configuration byte-for-byte
	restoredBytes, err := os.ReadFile(npmrcPath)
	if err != nil {
		t.Fatalf("failed reading restored .npmrc: %v", err)
	}
	if !bytes.Equal(restoredBytes, originalContent) {
		t.Fatalf("byte mismatch after recovery!\nGot:  %q\nWant: %q", string(restoredBytes), string(originalContent))
	}

	// 6. VERIFY: Journal is cleared and persistent state is disabled
	journalTx, err := freshStore.ReadJournal()
	if err != nil {
		t.Fatalf("ReadJournal failed: %v", err)
	}
	if journalTx != nil {
		t.Fatalf("expected journal to be cleared after recovery, found: %+v", journalTx)
	}

	st, err := freshStore.LoadState()
	if err != nil {
		t.Fatalf("LoadState failed: %v", err)
	}
	if st.Enabled {
		t.Fatalf("expected state Enabled=false after rollback")
	}
}

// TestCrashRecovery_InterruptedDisableRestoresPriorConfigurationByteForByte proves that
// a disable operation interrupted mid-transaction recovers cleanly without manual repair.
func TestCrashRecovery_InterruptedDisableRestoresPriorConfigurationByteForByte(t *testing.T) {
	tempDir := t.TempDir()
	dataDir := filepath.Join(tempDir, "data")
	npmrcPath := filepath.Join(tempDir, ".npmrc")

	originalContent := []byte("registry=https://custom-upstream.internal/\n")
	prior := PriorConfig{
		FileExisted: true,
		RawContent:  originalContent,
	}

	// Initial active state with gateway enabled
	stateStore, err := NewFileStateStore(dataDir)
	if err != nil {
		t.Fatalf("NewFileStateStore failed: %v", err)
	}
	_ = stateStore.SaveState(&GatewayState{
		Enabled:     true,
		GatewayURL:  "http://127.0.0.1:8765",
		PriorConfig: &prior,
	})

	// Current file has gateway config
	gatewayContent := []byte("registry=http://127.0.0.1:8765\n")
	if err := os.WriteFile(npmrcPath, gatewayContent, 0o644); err != nil {
		t.Fatalf("failed setting up gateway config: %v", err)
	}

	// Begin disable transaction
	tx, err := BeginTransaction(stateStore, ActionDisable, npmrcPath, "http://127.0.0.1:8765", prior)
	if err != nil {
		t.Fatalf("BeginTransaction failed: %v", err)
	}

	// Stage restoration of prior content
	stagedFile, err := StageTransaction(stateStore, tx, originalContent)
	if err != nil {
		t.Fatalf("StageTransaction failed: %v", err)
	}

	// Crash simulation mid-transaction
	freshStore, err := NewFileStateStore(dataDir)
	if err != nil {
		t.Fatalf("NewFileStateStore failed: %v", err)
	}

	res, err := RecoverJournal(freshStore)
	if err != nil {
		t.Fatalf("RecoverJournal failed: %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil RecoveryResult")
	}
	if res.Status != "completed" {
		t.Fatalf("expected status 'completed', got %q", res.Status)
	}

	// Cleaned up staged file
	if _, err := os.Stat(stagedFile); !os.IsNotExist(err) {
		t.Fatalf("expected staged file %s to be cleaned up", stagedFile)
	}

	// Exact prior configuration restored byte-for-byte
	finalBytes, err := os.ReadFile(npmrcPath)
	if err != nil {
		t.Fatalf("failed reading recovered .npmrc: %v", err)
	}
	if !bytes.Equal(finalBytes, originalContent) {
		t.Fatalf("byte mismatch after disable recovery!\nGot:  %q\nWant: %q", string(finalBytes), string(originalContent))
	}
}

// TestCrashRecovery_PreCommitInterruptSimulatedViaHook proves recovery when commit itself is interrupted.
func TestCrashRecovery_PreCommitInterruptSimulatedViaHook(t *testing.T) {
	tempDir := t.TempDir()
	dataDir := filepath.Join(tempDir, "data")
	npmrcPath := filepath.Join(tempDir, ".npmrc")

	stateStore, _ := NewFileStateStore(dataDir)
	prior := PriorConfig{FileExisted: false}

	tx, _ := BeginTransaction(stateStore, ActionEnable, npmrcPath, "http://127.0.0.1:8765", prior)
	_, _ = StageTransaction(stateStore, tx, []byte("registry=http://127.0.0.1:8765\n"))

	// Simulate panic / process crash in onPreCommit hook
	preCommitErr := errors.New("abrupt process kill right before atomic rename")
	var hookTriggered bool

	func() {
		defer func() {
			if r := recover(); r != nil {
				hookTriggered = true
			}
		}()
		_ = CommitTransaction(stateStore, tx, func() {
			panic(preCommitErr)
		})
	}()

	if !hookTriggered {
		t.Fatal("expected preCommit panic to trigger")
	}

	// Recover on next startup
	freshStore, _ := NewFileStateStore(dataDir)
	res, err := RecoverJournal(freshStore)
	if err != nil {
		t.Fatalf("RecoverJournal failed: %v", err)
	}
	if res.Status != "rolled_back" {
		t.Fatalf("expected status 'rolled_back', got %q", res.Status)
	}

	// Prior did not exist, so .npmrc must not exist
	if _, err := os.Stat(npmrcPath); !os.IsNotExist(err) {
		t.Fatalf("expected %s to not exist after rolling back non-existent prior file", npmrcPath)
	}
}
