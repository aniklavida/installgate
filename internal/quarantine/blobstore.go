package quarantine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
)

var (
	ErrBlobNotFound      = errors.New("blob not found")
	ErrBlobExceedsBudget = errors.New("blob size exceeds maximum disk budget")
	ErrBudgetExceeded    = errors.New("disk budget exceeded: active blobs are pinned mid-inspection or mid-release")
	ErrBlobPinned        = errors.New("cannot evict or delete blob: active inspection or release lease in progress")
)

// DiskBudget specifies an explicit disk-size limit for quarantined blobs.
// No implicit defaults are allowed.
type DiskBudget struct {
	MaxBytes int64
}

// Validate ensures the disk budget is explicitly and positively configured.
func (b DiskBudget) Validate() error {
	if b.MaxBytes <= 0 {
		return errors.New("quarantine: explicit MaxBytes budget greater than zero is required")
	}
	return nil
}

// BlobStore manages crash-safe, content-addressed storage and eviction for package blobs.
type BlobStore interface {
	Put(ctx context.Context, key string, src io.Reader) (int64, error)
	PutVerified(ctx context.Context, key string, src io.Reader, expected ParsedDigest) (int64, error)
	Get(ctx context.Context, key string) (io.ReadCloser, int64, error)
	Has(ctx context.Context, key string) bool
	Delete(ctx context.Context, key string) error
	Pin(key string) (func(), error)
	IsPinned(key string) bool
	TotalBytes() int64
	BlobPath(key string) string
}

// DiskBlobStore implements BlobStore on the local filesystem.
type DiskBlobStore struct {
	rootDir      string
	blobsDir     string
	stagingDir   string
	budget       DiskBudget
	metadata     MetadataStore
	mu           sync.Mutex
	pins         map[string]int
	currentBytes int64
}

// NewDiskBlobStore initializes a disk-backed content-addressed blob store.
func NewDiskBlobStore(rootDir string, budget DiskBudget, metadata MetadataStore) (*DiskBlobStore, error) {
	if err := budget.Validate(); err != nil {
		return nil, err
	}
	if rootDir == "" {
		return nil, errors.New("quarantine: root directory cannot be empty")
	}
	if metadata == nil {
		return nil, errors.New("quarantine: metadata store is required")
	}

	blobsDir := filepath.Join(rootDir, "blobs")
	stagingDir := filepath.Join(rootDir, "staging")

	if err := os.MkdirAll(blobsDir, 0o700); err != nil {
		return nil, fmt.Errorf("failed creating blobs directory: %w", err)
	}
	if err := os.MkdirAll(stagingDir, 0o700); err != nil {
		return nil, fmt.Errorf("failed creating staging directory: %w", err)
	}

	// Clean up any stale staging files from prior interrupted processes.
	// This ensures an interrupted fetch leaves nothing that could be mistaken for valid entries.
	if entries, err := os.ReadDir(stagingDir); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				_ = os.Remove(filepath.Join(stagingDir, entry.Name()))
			}
		}
	}

	// Calculate initial size of existing valid blobs
	var initialBytes int64
	if entries, err := os.ReadDir(blobsDir); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				if info, err := entry.Info(); err == nil {
					initialBytes += info.Size()
				}
			}
		}
	}

	return &DiskBlobStore{
		rootDir:      rootDir,
		blobsDir:     blobsDir,
		stagingDir:   stagingDir,
		budget:       budget,
		metadata:     metadata,
		pins:         make(map[string]int),
		currentBytes: initialBytes,
	}, nil
}

// BlobPath returns the absolute disk path for a blob key.
func (s *DiskBlobStore) BlobPath(key string) string {
	return filepath.Join(s.blobsDir, key)
}

// TotalBytes returns the current byte count consumed by stored blobs.
func (s *DiskBlobStore) TotalBytes() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.currentBytes
}

// Has reports whether the blob key already exists in the store.
func (s *DiskBlobStore) Has(ctx context.Context, key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	targetPath := s.BlobPath(key)
	_, err := os.Stat(targetPath)
	return err == nil
}

// Put writes data from src into the content-addressed store under key.
// It is crash-safe: writes occur to a staging file, and only rename to blobs/
// after the full stream has completed without error.
func (s *DiskBlobStore) Put(ctx context.Context, key string, src io.Reader) (int64, error) {
	return s.putInternal(ctx, key, src, nil)
}

// PutVerified writes data from src while simultaneously calculating its digest.
// It verifies the digest against expected BEFORE committing to blobs/. If the digest
// does not match, the staging file is deleted immediately and ErrIntegrityMismatch is returned.
func (s *DiskBlobStore) PutVerified(ctx context.Context, key string, src io.Reader, expected ParsedDigest) (int64, error) {
	return s.putInternal(ctx, key, src, &expected)
}

func (s *DiskBlobStore) putInternal(ctx context.Context, key string, src io.Reader, expected *ParsedDigest) (int64, error) {
	if key == "" {
		return 0, errors.New("blob key cannot be empty")
	}

	targetPath := s.BlobPath(key)

	// Check if already present to deduplicate content
	s.mu.Lock()
	if info, err := os.Stat(targetPath); err == nil {
		s.mu.Unlock()
		return info.Size(), nil
	}
	s.mu.Unlock()

	// 1. Write to isolated staging directory
	tmpFile, err := os.CreateTemp(s.stagingDir, "ingest_*.tmp")
	if err != nil {
		return 0, fmt.Errorf("failed creating staging file: %w", err)
	}
	tmpPath := tmpFile.Name()

	var writeSuccess bool
	defer func() {
		_ = tmpFile.Close()
		if !writeSuccess {
			_ = os.Remove(tmpPath)
		}
	}()

	var reader io.Reader = src
	var hasher io.Writer
	var h interface{ Sum([]byte) []byte }

	if expected != nil {
		newHasher, err := HasherFor(expected.Algorithm)
		if err != nil {
			return 0, err
		}
		hasher = newHasher
		h = newHasher
		reader = io.TeeReader(src, hasher)
	}

	written, err := io.Copy(tmpFile, reader)
	if err != nil {
		return 0, fmt.Errorf("interrupted write to staging file: %w", err)
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return 0, fmt.Errorf("context cancelled during write: %w", ctxErr)
	}

	// First integrity verification: verify computed digest matches expected digest before committing
	if expected != nil && h != nil {
		computedBytes := h.Sum(nil)
		if !bytes.Equal(computedBytes, expected.Bytes) {
			return 0, ErrIntegrityMismatch
		}
	}

	if err := tmpFile.Sync(); err != nil {
		return 0, fmt.Errorf("failed syncing staging file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return 0, fmt.Errorf("failed closing staging file: %w", err)
	}

	if written > s.budget.MaxBytes {
		return 0, fmt.Errorf("%w: blob is %d bytes, max budget is %d bytes",
			ErrBlobExceedsBudget, written, s.budget.MaxBytes)
	}

	// 2. Commit to store under lock, executing eviction if needed
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check again under lock in case another goroutine just committed this key
	if info, err := os.Stat(targetPath); err == nil {
		writeSuccess = false // discard duplicate staging file
		return info.Size(), nil
	}

	// Evict unpinned blobs if adding this blob would exceed disk budget
	for s.currentBytes+written > s.budget.MaxBytes {
		evictedBytes, err := s.evictOneCandidateLocked(ctx)
		if err != nil {
			return 0, fmt.Errorf("%w: %v", ErrBudgetExceeded, err)
		}
		s.currentBytes -= evictedBytes
	}

	// Set safe permissions before moving into place
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return 0, fmt.Errorf("failed setting blob permissions: %w", err)
	}

	// Atomically move from staging into content-addressed blobs directory
	if err := os.Rename(tmpPath, targetPath); err != nil {
		return 0, fmt.Errorf("failed committing blob to store: %w", err)
	}

	writeSuccess = true
	s.currentBytes += written

	return written, nil
}

// evictOneCandidateLocked selects the least recently accessed unpinned blob and removes it.
// It will NEVER evict a blob that has an active pin (mid-inspection or mid-release).
func (s *DiskBlobStore) evictOneCandidateLocked(ctx context.Context) (int64, error) {
	records, err := s.metadata.List(ctx)
	if err != nil {
		return 0, fmt.Errorf("failed querying metadata for eviction: %w", err)
	}

	for _, candidate := range records {
		key := candidate.Digest
		// NEVER evict a blob that is currently pinned
		if s.pins[key] > 0 {
			continue
		}

		blobPath := s.BlobPath(key)
		info, statErr := os.Stat(blobPath)

		// Delete blob file
		_ = os.Remove(blobPath)
		// Delete metadata record
		_ = s.metadata.Delete(ctx, key)

		if statErr == nil && info != nil {
			return info.Size(), nil
		}
		return candidate.Size, nil
	}

	return 0, errors.New("no unpinned blobs available for eviction")
}

// Get opens a read-only stream to an existing blob.
func (s *DiskBlobStore) Get(ctx context.Context, key string) (io.ReadCloser, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	targetPath := s.BlobPath(key)
	file, err := os.Open(targetPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, ErrBlobNotFound
		}
		return nil, 0, err
	}

	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, 0, err
	}

	return file, info.Size(), nil
}

// Pin places an active reference on a blob, guaranteeing it will NEVER be evicted
// while mid-inspection or mid-release. The caller must call the returned unpin function
// when the active operation concludes.
func (s *DiskBlobStore) Pin(key string) (func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	targetPath := s.BlobPath(key)
	if _, err := os.Stat(targetPath); err != nil {
		if os.IsNotExist(err) {
			return nil, ErrBlobNotFound
		}
		return nil, err
	}

	s.pins[key]++

	var unpinned int32
	unpin := func() {
		if atomic.CompareAndSwapInt32(&unpinned, 0, 1) {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.pins[key]--
			if s.pins[key] <= 0 {
				delete(s.pins, key)
			}
		}
	}

	return unpin, nil
}

// IsPinned reports whether a blob currently has an active pin.
func (s *DiskBlobStore) IsPinned(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pins[key] > 0
}

// Delete removes a blob from the store. Returns ErrBlobPinned if the blob is currently in use.
func (s *DiskBlobStore) Delete(ctx context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.pins[key] > 0 {
		return ErrBlobPinned
	}

	targetPath := s.BlobPath(key)
	info, statErr := os.Stat(targetPath)
	if err := os.Remove(targetPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	if statErr == nil && info != nil {
		s.currentBytes -= info.Size()
		if s.currentBytes < 0 {
			s.currentBytes = 0
		}
	}

	_ = s.metadata.Delete(ctx, key)
	return nil
}
