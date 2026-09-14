package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// RecoveryResult details the outcome of recovering an interrupted transaction.
type RecoveryResult struct {
	Action     ActionKind `json:"action"`
	Status     string     `json:"status"`
	TargetFile string     `json:"target_file"`
	Message    string     `json:"message"`
}

// GenerateTransactionID generates a unique, timestamp-prefixed transaction ID.
func GenerateTransactionID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("tx_%d_%s", time.Now().UnixNano(), hex.EncodeToString(b))
}

// BeginTransaction creates and durably writes a pending transaction record.
func BeginTransaction(store StateStore, action ActionKind, targetFile, gatewayURL string, prior PriorConfig) (*Transaction, error) {
	now := time.Now().UTC()
	tx := &Transaction{
		ID:          GenerateTransactionID(),
		Action:      action,
		Phase:       PhasePending,
		TargetFile:  targetFile,
		GatewayURL:  gatewayURL,
		PriorConfig: prior,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if err := store.WriteJournal(tx); err != nil {
		return nil, fmt.Errorf("failed to persist transaction journal: %w", err)
	}
	return tx, nil
}

// StageTransaction writes replacement content to a temporary sibling file and updates the journal.
func StageTransaction(store StateStore, tx *Transaction, content []byte) (string, error) {
	dir := filepath.Dir(tx.TargetFile)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("failed to prepare directory for staging: %w", err)
	}

	tmpFile, err := os.CreateTemp(dir, ".npmrc.ig_staged_*.tmp")
	if err != nil {
		return "", fmt.Errorf("failed to create staged file: %w", err)
	}
	stagedPath := tmpFile.Name()

	writeErr := func() error {
		if _, err := tmpFile.Write(content); err != nil {
			return err
		}
		if err := tmpFile.Sync(); err != nil {
			return err
		}
		return tmpFile.Close()
	}()

	if writeErr != nil {
		_ = tmpFile.Close()
		_ = os.Remove(stagedPath)
		return "", fmt.Errorf("failed to write staged file: %w", writeErr)
	}

	tx.Phase = PhaseStaged
	tx.StagedFile = stagedPath
	tx.UpdatedAt = time.Now().UTC()

	if err := store.WriteJournal(tx); err != nil {
		_ = os.Remove(stagedPath)
		return "", fmt.Errorf("failed to update transaction journal to staged: %w", err)
	}

	return stagedPath, nil
}

// CommitTransaction atomically moves the staged file to the target location, updates state, and clears the journal.
// onPreCommit is an optional hook called immediately before the file commit, used by tests to simulate process interruptions.
func CommitTransaction(store StateStore, tx *Transaction, onPreCommit func()) error {
	if onPreCommit != nil {
		onPreCommit()
	}

	if tx.Action == ActionEnable {
		if tx.StagedFile == "" {
			return fmt.Errorf("cannot commit enable transaction without staged file")
		}
		if err := os.Rename(tx.StagedFile, tx.TargetFile); err != nil {
			return fmt.Errorf("failed to commit enabled configuration: %w", err)
		}
		_ = os.Chmod(tx.TargetFile, 0o644)
	} else if tx.Action == ActionDisable {
		if !tx.PriorConfig.FileExisted {
			// Prior state had no file; remove target
			if err := os.Remove(tx.TargetFile); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("failed to remove disabled configuration file: %w", err)
			}
		} else {
			if tx.StagedFile == "" {
				return fmt.Errorf("cannot commit disable transaction without staged file")
			}
			if err := os.Rename(tx.StagedFile, tx.TargetFile); err != nil {
				return fmt.Errorf("failed to commit restored configuration: %w", err)
			}
			_ = os.Chmod(tx.TargetFile, 0o644)
		}
	}

	tx.Phase = PhaseCommitted
	tx.UpdatedAt = time.Now().UTC()

	// Update persistent state
	state, err := store.LoadState()
	if err != nil || state == nil {
		state = &GatewayState{}
	}
	if tx.Action == ActionEnable {
		state.Enabled = true
		state.GatewayURL = tx.GatewayURL
		priorCopy := tx.PriorConfig
		state.PriorConfig = &priorCopy
	} else {
		state.Enabled = false
		state.PriorConfig = nil
	}
	state.LastUpdated = tx.UpdatedAt
	_ = store.SaveState(state)

	// Clear journal upon clean commit
	if err := store.ClearJournal(); err != nil {
		return fmt.Errorf("failed to clear transaction journal: %w", err)
	}

	return nil
}

// RecoverJournal inspects durable storage for an uncommitted transaction and safely completes or rolls it back.
func RecoverJournal(store StateStore) (*RecoveryResult, error) {
	tx, err := store.ReadJournal()
	if err != nil {
		return nil, fmt.Errorf("failed to inspect transaction journal: %w", err)
	}
	if tx == nil {
		return nil, nil
	}

	// Clean up any dangling staged temp file
	if tx.StagedFile != "" {
		_ = os.Remove(tx.StagedFile)
	}

	// Interrupted enable or disable: both recover to the exact prior configuration byte-for-byte.
	// For enable: roll back to prior configuration so npm never points at a dead gateway.
	// For disable: complete the restoration of the prior configuration.
	if !tx.PriorConfig.FileExisted {
		// File did not exist previously: ensure target file is removed
		if err := os.Remove(tx.TargetFile); err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("recovery failed to remove target file %s: %w", tx.TargetFile, err)
		}
	} else {
		// Restore exact prior content
		if err := atomicWriteFile(tx.TargetFile, tx.PriorConfig.RawContent, 0o644); err != nil {
			return nil, fmt.Errorf("recovery failed to restore target file %s: %w", tx.TargetFile, err)
		}
	}

	// Reset state to disabled and clear journal
	state, _ := store.LoadState()
	if state == nil {
		state = &GatewayState{}
	}
	state.Enabled = false
	state.PriorConfig = nil
	state.LastUpdated = time.Now().UTC()
	_ = store.SaveState(state)

	if err := store.ClearJournal(); err != nil {
		return nil, fmt.Errorf("recovery failed to clear journal: %w", err)
	}

	status := "rolled_back"
	msg := fmt.Sprintf("interrupted %s transaction %s recovered: restored prior registry configuration byte-for-byte", tx.Action, tx.ID)
	if tx.Action == ActionDisable {
		status = "completed"
		msg = fmt.Sprintf("interrupted disable transaction %s recovered: restored prior registry configuration byte-for-byte", tx.ID)
	}

	return &RecoveryResult{
		Action:     tx.Action,
		Status:     status,
		TargetFile: tx.TargetFile,
		Message:    msg,
	}, nil
}
