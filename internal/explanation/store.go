package explanation

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
)

// ErrDecisionNotFound is returned when a requested decision ID does not exist.
var ErrDecisionNotFound = errors.New("decision not found")

var validDecisionIDRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-]+$`)

// DecisionStore persists and retrieves decision documents.
type DecisionStore interface {
	Save(doc *DecisionDocument) error
	Get(decisionID string) (*DecisionDocument, error)
}

// MemoryStore provides a thread-safe, in-memory DecisionStore.
type MemoryStore struct {
	mu        sync.RWMutex
	decisions map[string]*DecisionDocument
}

// NewMemoryStore creates an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		decisions: make(map[string]*DecisionDocument),
	}
}

// Save stores a decision document in memory.
func (m *MemoryStore) Save(doc *DecisionDocument) error {
	if doc == nil {
		return errors.New("cannot save nil decision document")
	}
	if doc.DecisionID == "" {
		return errors.New("decision document must have an ID")
	}

	data, err := RenderJSON(doc)
	if err != nil {
		return err
	}
	cloned, err := ParseJSON(data)
	if err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.decisions[doc.DecisionID] = cloned
	return nil
}

// Get retrieves a decision document by its identifier from memory.
func (m *MemoryStore) Get(decisionID string) (*DecisionDocument, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	doc, ok := m.decisions[decisionID]
	if !ok {
		return nil, ErrDecisionNotFound
	}

	data, err := RenderJSON(doc)
	if err != nil {
		return nil, err
	}
	return ParseJSON(data)
}

// FileStore persists decision documents as JSON files in a dedicated directory.
type FileStore struct {
	mu  sync.RWMutex
	dir string
}

// NewFileStore constructs a FileStore in the specified directory.
func NewFileStore(dir string) (*FileStore, error) {
	if dir == "" {
		return nil, errors.New("directory path cannot be empty")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to initialize decision store directory %q: %w", dir, err)
	}
	return &FileStore{dir: dir}, nil
}

// Save writes a decision document atomically to the filesystem.
func (f *FileStore) Save(doc *DecisionDocument) error {
	if doc == nil {
		return errors.New("cannot save nil decision document")
	}
	if doc.DecisionID == "" {
		return errors.New("decision document must have an ID")
	}
	if !validDecisionIDRegex.MatchString(doc.DecisionID) {
		return fmt.Errorf("invalid decision ID format: %q", doc.DecisionID)
	}

	data, err := RenderJSON(doc)
	if err != nil {
		return err
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	targetPath := filepath.Join(f.dir, doc.DecisionID+".json")
	tmpFile, err := os.CreateTemp(f.dir, "dec_*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp decision file: %w", err)
	}
	tmpName := tmpFile.Name()

	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpName)
	}()

	if _, err := tmpFile.Write(data); err != nil {
		return fmt.Errorf("failed to write decision data: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		return fmt.Errorf("failed to sync decision data: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp decision file: %w", err)
	}

	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("failed to set decision file permissions: %w", err)
	}

	if err := os.Rename(tmpName, targetPath); err != nil {
		return fmt.Errorf("failed to atomically commit decision file: %w", err)
	}

	return nil
}

// Get reads and decodes a decision document by identifier.
func (f *FileStore) Get(decisionID string) (*DecisionDocument, error) {
	if !validDecisionIDRegex.MatchString(decisionID) {
		return nil, fmt.Errorf("invalid decision ID format: %q", decisionID)
	}

	f.mu.RLock()
	defer f.mu.RUnlock()

	targetPath := filepath.Join(f.dir, decisionID+".json")
	data, err := os.ReadFile(targetPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrDecisionNotFound
		}
		return nil, fmt.Errorf("failed to read decision file %q: %w", targetPath, err)
	}

	return ParseJSON(data)
}

// DefaultDecisionDir returns the canonical directory path for storing decisions.
func DefaultDecisionDir() string {
	if dir := os.Getenv("INSTALLGATE_DATA_DIR"); dir != "" {
		return filepath.Join(dir, "decisions")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".installgate", "decisions")
	}
	return filepath.Join(".installgate", "decisions")
}

// DefaultStore returns a FileStore initialized with the default decision directory.
func DefaultStore() DecisionStore {
	store, err := NewFileStore(DefaultDecisionDir())
	if err != nil {
		// Fall back safely to in-memory store if directory initialization fails
		return NewMemoryStore()
	}
	return store
}

// Resolve retrieves a decision document from a store or an explicit file path.
func Resolve(target string, store DecisionStore) (*DecisionDocument, error) {
	if target == "" {
		return nil, errors.New("decision identifier or file path is required")
	}

	// Check if target is an explicit existing file on disk
	if info, err := os.Stat(target); err == nil && !info.IsDir() {
		data, err := os.ReadFile(target)
		if err != nil {
			return nil, fmt.Errorf("failed to read decision file %q: %w", target, err)
		}
		return ParseJSON(data)
	}

	if store == nil {
		return nil, errors.New("decision store is required to resolve identifier")
	}

	doc, err := store.Get(target)
	if err != nil {
		if errors.Is(err, ErrDecisionNotFound) {
			return nil, fmt.Errorf("decision %q not found", target)
		}
		return nil, err
	}

	return doc, nil
}
