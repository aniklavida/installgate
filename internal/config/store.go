package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ErrNoActiveJournal indicates there is no active transaction journal record.
var ErrNoActiveJournal = errors.New("no active transaction journal")

// ActionKind indicates whether a configuration transaction is enabling or disabling InstallGate.
type ActionKind string

const (
	ActionEnable  ActionKind = "enable"
	ActionDisable ActionKind = "disable"
)

// TransactionPhase tracks progress through the multi-step configuration update.
type TransactionPhase string

const (
	PhasePending   TransactionPhase = "pending"   // journal written to durable storage
	PhaseStaged    TransactionPhase = "staged"    // temp replacement file written and synced
	PhaseCommitted TransactionPhase = "committed" // replacement file renamed to target
)

// PriorConfig records the exact state of an npm configuration file prior to modification.
type PriorConfig struct {
	FileExisted   bool   `json:"file_existed"`
	HasRegistry   bool   `json:"has_registry"`
	RegistryValue string `json:"registry_value,omitempty"`
	RawContent    []byte `json:"raw_content,omitempty"`
}

// Transaction represents a durable record of an in-flight configuration change.
type Transaction struct {
	ID          string           `json:"id"`
	Action      ActionKind       `json:"action"`
	Phase       TransactionPhase `json:"phase"`
	TargetFile  string           `json:"target_file"`
	GatewayURL  string           `json:"gateway_url,omitempty"`
	StagedFile  string           `json:"staged_file,omitempty"`
	PriorConfig PriorConfig      `json:"prior_config"`
	CreatedAt   time.Time        `json:"created_at"`
	UpdatedAt   time.Time        `json:"updated_at"`
}

// GatewayState records the persistent operational and registry status of InstallGate.
type GatewayState struct {
	Enabled     bool         `json:"enabled"`
	GatewayURL  string       `json:"gateway_url,omitempty"`
	Port        int          `json:"port,omitempty"`
	PID         int          `json:"pid,omitempty"`
	PriorConfig *PriorConfig `json:"prior_config,omitempty"`
	LastUpdated time.Time    `json:"last_updated"`
}

// StateStore provides the storage interface for lifecycle state and the transaction journal.
// Persistent configuration history and the database store are implemented separately;
// building against this interface allows storage substitution without changing lifecycle logic.
type StateStore interface {
	WriteJournal(tx *Transaction) error
	ReadJournal() (*Transaction, error)
	ClearJournal() error
	SaveState(state *GatewayState) error
	LoadState() (*GatewayState, error)
}

// FileStateStore implements StateStore using atomic file operations in a specified directory.
type FileStateStore struct {
	mu  sync.RWMutex
	dir string
}

// NewFileStateStore constructs a FileStateStore rooted in the specified directory.
func NewFileStateStore(dir string) (*FileStateStore, error) {
	if dir == "" {
		return nil, errors.New("state store directory cannot be empty")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create state directory: %w", err)
	}
	return &FileStateStore{dir: dir}, nil
}

func (s *FileStateStore) journalPath() string {
	return filepath.Join(s.dir, "journal.json")
}

func (s *FileStateStore) statePath() string {
	return filepath.Join(s.dir, "state.json")
}

// WriteJournal durably persists an active transaction record.
func (s *FileStateStore) WriteJournal(tx *Transaction) error {
	if tx == nil {
		return errors.New("cannot write nil transaction")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.MarshalIndent(tx, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal transaction: %w", err)
	}
	return atomicWriteFile(s.journalPath(), data, 0o600)
}

// ReadJournal reads the active transaction journal if present.
func (s *FileStateStore) ReadJournal() (*Transaction, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := os.ReadFile(s.journalPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read journal: %w", err)
	}

	var tx Transaction
	if err := json.Unmarshal(data, &tx); err != nil {
		return nil, fmt.Errorf("corrupt journal file: %w", err)
	}
	return &tx, nil
}

// ClearJournal removes the journal file upon successful completion or rollback.
func (s *FileStateStore) ClearJournal() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	err := os.Remove(s.journalPath())
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove journal: %w", err)
	}
	return nil
}

// SaveState saves the current gateway lifecycle state.
func (s *FileStateStore) SaveState(state *GatewayState) error {
	if state == nil {
		return errors.New("cannot save nil state")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal state: %w", err)
	}
	return atomicWriteFile(s.statePath(), data, 0o600)
}

// LoadState reads the gateway lifecycle state.
func (s *FileStateStore) LoadState() (*GatewayState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := os.ReadFile(s.statePath())
	if err != nil {
		if os.IsNotExist(err) {
			return &GatewayState{Enabled: false}, nil
		}
		return nil, fmt.Errorf("failed to read state: %w", err)
	}

	var state GatewayState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("corrupt state file: %w", err)
	}
	return &state, nil
}

func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "ig_*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpName := tmp.Name()

	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()

	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("failed to sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		return fmt.Errorf("failed to chmod temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("failed to rename temp file: %w", err)
	}
	return nil
}
