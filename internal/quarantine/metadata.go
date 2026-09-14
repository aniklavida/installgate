package quarantine

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

var (
	ErrMetadataNotFound = errors.New("blob metadata not found")
)

// BlobStatus represents the lifecycle state of a quarantined blob.
type BlobStatus string

const (
	StatusQuarantined BlobStatus = "quarantined"
	StatusInspected   BlobStatus = "inspected"
	StatusVerified    BlobStatus = "verified"
	StatusReleased    BlobStatus = "released"
	StatusBlocked     BlobStatus = "blocked"
)

// BlobMetadata tracks operational records for a content-addressed blob.
// Metadata resides strictly in the metadata store, separated from blob bytes.
type BlobMetadata struct {
	Digest         string     `json:"digest"`
	Package        string     `json:"package"`
	Version        string     `json:"version"`
	Size           int64      `json:"size"`
	Status         BlobStatus `json:"status"`
	CreatedAt      time.Time  `json:"created_at"`
	LastAccessedAt time.Time  `json:"last_accessed_at"`
}

// MetadataStore defines the interface for persisting and querying blob records.
type MetadataStore interface {
	Put(ctx context.Context, meta BlobMetadata) error
	Get(ctx context.Context, digest string) (BlobMetadata, error)
	Touch(ctx context.Context, digest string, t time.Time) error
	UpdateStatus(ctx context.Context, digest string, status BlobStatus) error
	Delete(ctx context.Context, digest string) error
	List(ctx context.Context) ([]BlobMetadata, error)
}

// MemoryMetadataStore provides a thread-safe in-memory implementation of MetadataStore.
type MemoryMetadataStore struct {
	mu      sync.RWMutex
	records map[string]BlobMetadata
}

// NewMemoryMetadataStore constructs an empty in-memory metadata store.
func NewMemoryMetadataStore() *MemoryMetadataStore {
	return &MemoryMetadataStore{
		records: make(map[string]BlobMetadata),
	}
}

// Put records or updates blob metadata.
func (s *MemoryMetadataStore) Put(ctx context.Context, meta BlobMetadata) error {
	if meta.Digest == "" {
		return errors.New("blob metadata digest cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if meta.CreatedAt.IsZero() {
		meta.CreatedAt = time.Now().UTC()
	}
	if meta.LastAccessedAt.IsZero() {
		meta.LastAccessedAt = meta.CreatedAt
	}

	s.records[meta.Digest] = meta
	return nil
}

// Get retrieves metadata for a given blob digest.
func (s *MemoryMetadataStore) Get(ctx context.Context, digest string) (BlobMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	meta, ok := s.records[digest]
	if !ok {
		return BlobMetadata{}, fmt.Errorf("%w: %s", ErrMetadataNotFound, digest)
	}
	return meta, nil
}

// Touch updates the last accessed timestamp for a blob, used for LRU ordering.
func (s *MemoryMetadataStore) Touch(ctx context.Context, digest string, t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	meta, ok := s.records[digest]
	if !ok {
		return fmt.Errorf("%w: %s", ErrMetadataNotFound, digest)
	}
	meta.LastAccessedAt = t.UTC()
	s.records[digest] = meta
	return nil
}

// UpdateStatus sets the lifecycle state of a blob.
func (s *MemoryMetadataStore) UpdateStatus(ctx context.Context, digest string, status BlobStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	meta, ok := s.records[digest]
	if !ok {
		return fmt.Errorf("%w: %s", ErrMetadataNotFound, digest)
	}
	meta.Status = status
	s.records[digest] = meta
	return nil
}

// Delete removes metadata for a given blob digest.
func (s *MemoryMetadataStore) Delete(ctx context.Context, digest string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.records, digest)
	return nil
}

// List returns a copy of all metadata records, sorted by LastAccessedAt ascending (oldest first).
func (s *MemoryMetadataStore) List(ctx context.Context) ([]BlobMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	res := make([]BlobMetadata, 0, len(s.records))
	for _, m := range s.records {
		res = append(res, m)
	}

	sort.Slice(res, func(i, j int) bool {
		return res[i].LastAccessedAt.Before(res[j].LastAccessedAt)
	})

	return res, nil
}
