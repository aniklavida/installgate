package quarantine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// QuarantinedEntry represents a package tarball held in quarantine awaiting
// inspection and policy evaluation. It holds an active pin preventing eviction.
type QuarantinedEntry struct {
	Key               string
	ExpectedIntegrity string
	Package           string
	Version           string
	Size              int64
	unpinInspection   func()
}

// Config configures the quarantine Manager.
type Config struct {
	Store         BlobStore
	Metadata      MetadataStore
	Limits        ArchiveLimits
	InspectLimits InspectLimits
	Clock         func() time.Time
}

// Manager coordinates content-addressed ingestion, double integrity verification,
// archive safety inspection, and safe pinned release.
type Manager struct {
	store         BlobStore
	metadata      MetadataStore
	limits        ArchiveLimits
	inspectLimits InspectLimits
	clock         func() time.Time
}

// NewManager constructs a quarantine Manager with validated configuration.
func NewManager(cfg Config) (*Manager, error) {
	if cfg.Store == nil {
		return nil, errors.New("quarantine: store is required")
	}
	if cfg.Metadata == nil {
		return nil, errors.New("quarantine: metadata store is required")
	}
	if err := cfg.Limits.Validate(); err != nil {
		return nil, err
	}

	inspectLimits := cfg.InspectLimits
	if inspectLimits.MaxScriptBytes == 0 {
		inspectLimits = DefaultInspectLimits()
	}
	if err := inspectLimits.Validate(); err != nil {
		return nil, err
	}

	clock := cfg.Clock
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}

	return &Manager{
		store:         cfg.Store,
		metadata:      cfg.Metadata,
		limits:        cfg.Limits,
		inspectLimits: inspectLimits,
		clock:         clock,
	}, nil
}

// Store returns the underlying BlobStore.
func (m *Manager) Store() BlobStore {
	return m.store
}

// Metadata returns the underlying MetadataStore.
func (m *Manager) Metadata() MetadataStore {
	return m.metadata
}

// Limits returns the active archive inspection limits.
func (m *Manager) Limits() ArchiveLimits {
	return m.limits
}

// InspectLimits returns the active static script inspection limits.
func (m *Manager) InspectLimits() InspectLimits {
	return m.inspectLimits
}

// Ingest streams a package tarball into quarantine and performs the FIRST integrity verification.
// If the digest does not match expectedIntegrity, the staging bytes are deleted immediately and
// ErrIntegrityMismatch is returned. Upon success, the blob is pinned to prevent eviction during inspection.
func (m *Manager) Ingest(ctx context.Context, pkg, version, expectedIntegrity string, r io.Reader) (*QuarantinedEntry, error) {
	parsedExpected, err := ParseDigest(expectedIntegrity)
	if err != nil {
		return nil, fmt.Errorf("invalid expected integrity: %w", err)
	}

	key := parsedExpected.Key()
	now := m.clock()

	// Content-addressed deduplication: if already present in store, reuse existing entry
	if m.store.Has(ctx, key) {
		unpin, err := m.store.Pin(key)
		if err != nil {
			return nil, fmt.Errorf("failed pinning existing blob: %w", err)
		}

		_ = m.metadata.Touch(ctx, key, now)
		meta, err := m.metadata.Get(ctx, key)
		size := int64(0)
		if err == nil {
			size = meta.Size
		}

		return &QuarantinedEntry{
			Key:               key,
			ExpectedIntegrity: expectedIntegrity,
			Package:           pkg,
			Version:           version,
			Size:              size,
			unpinInspection:   unpin,
		}, nil
	}

	// 1. Crash-safe write with simultaneous FIRST INTEGRITY VERIFICATION
	size, err := m.store.PutVerified(ctx, key, r, parsedExpected)
	if err != nil {
		if errors.Is(err, ErrIntegrityMismatch) {
			// Record blocked integrity attempt in metadata store without persisting corrupted bytes
			_ = m.metadata.Put(ctx, BlobMetadata{
				Digest:         key,
				Package:        pkg,
				Version:        version,
				Size:           0,
				Status:         StatusBlocked,
				CreatedAt:      now,
				LastAccessedAt: now,
			})
			return nil, ErrIntegrityMismatch
		}
		return nil, err
	}

	// 2. Pin blob for active inspection
	unpin, err := m.store.Pin(key)
	if err != nil {
		return nil, fmt.Errorf("failed pinning blob for inspection: %w", err)
	}

	// 3. Record metadata in metadata store
	err = m.metadata.Put(ctx, BlobMetadata{
		Digest:         key,
		Package:        pkg,
		Version:        version,
		Size:           size,
		Status:         StatusQuarantined,
		CreatedAt:      now,
		LastAccessedAt: now,
	})
	if err != nil {
		unpin()
		return nil, fmt.Errorf("failed storing blob metadata: %w", err)
	}

	return &QuarantinedEntry{
		Key:               key,
		ExpectedIntegrity: expectedIntegrity,
		Package:           pkg,
		Version:           version,
		Size:              size,
		unpinInspection:   unpin,
	}, nil
}

// Inspect performs static inspection of an ingested quarantined blob.
// It releases the inspection pin upon completion.
func (m *Manager) Inspect(ctx context.Context, entry *QuarantinedEntry) (*ArchiveInspection, error) {
	if entry == nil {
		return nil, errors.New("cannot inspect nil quarantine entry")
	}
	defer func() {
		if entry.unpinInspection != nil {
			entry.unpinInspection()
			entry.unpinInspection = nil
		}
	}()

	reader, _, err := m.store.Get(ctx, entry.Key)
	if err != nil {
		_ = m.metadata.UpdateStatus(ctx, entry.Key, StatusBlocked)
		return nil, fmt.Errorf("failed opening blob for inspection: %w", err)
	}
	defer reader.Close()

	inspection, err := InspectArchiveWithLimits(ctx, reader, m.limits, m.inspectLimits, nil)
	if err != nil {
		_ = m.metadata.UpdateStatus(ctx, entry.Key, StatusBlocked)
		return nil, err
	}

	if len(inspection.DangerousScripts) > 0 {
		_ = m.metadata.UpdateStatus(ctx, entry.Key, StatusBlocked)
		return inspection, nil
	}

	_ = m.metadata.UpdateStatus(ctx, entry.Key, StatusInspected)
	return inspection, nil
}

// VerifyAndRelease performs the SECOND INTEGRITY VERIFICATION on the quarantined blob.
// This proves the blob was not modified or corrupted between inspection and release.
// If the digest matches, it returns a pinned stream that unpins automatically on Close.
func (m *Manager) VerifyAndRelease(ctx context.Context, key, expectedIntegrity string) (io.ReadCloser, int64, error) {
	parsedExpected, err := ParseDigest(expectedIntegrity)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid expected integrity: %w", err)
	}

	// 1. Pin blob for release: eviction can NEVER evict a blob mid-release
	unpin, err := m.store.Pin(key)
	if err != nil {
		return nil, 0, fmt.Errorf("failed pinning blob for release: %w", err)
	}

	// 2. Open blob from store and perform SECOND INTEGRITY VERIFICATION
	file, _, err := m.store.Get(ctx, key)
	if err != nil {
		unpin()
		return nil, 0, fmt.Errorf("failed opening blob for release: %w", err)
	}

	hasher, err := HasherFor(parsedExpected.Algorithm)
	if err != nil {
		_ = file.Close()
		unpin()
		return nil, 0, err
	}

	if _, err := io.Copy(hasher, file); err != nil {
		_ = file.Close()
		unpin()
		return nil, 0, fmt.Errorf("error reading blob during second verification: %w", err)
	}

	computed := hasher.Sum(nil)
	if !bytes.Equal(computed, parsedExpected.Bytes) {
		_ = file.Close()
		unpin()
		_ = m.metadata.UpdateStatus(ctx, key, StatusBlocked)
		return nil, 0, ErrIntegrityMismatchSecond
	}

	// Verification succeeded. Close verification reader and reopen for streaming
	_ = file.Close()

	stream, streamSize, err := m.store.Get(ctx, key)
	if err != nil {
		unpin()
		return nil, 0, fmt.Errorf("failed opening release stream: %w", err)
	}

	now := m.clock()
	_ = m.metadata.UpdateStatus(ctx, key, StatusReleased)
	_ = m.metadata.Touch(ctx, key, now)

	// Return stream that automatically unpins when closed by the HTTP handler
	return &releaseStream{
		ReadCloser: stream,
		unpin:      unpin,
	}, streamSize, nil
}

type releaseStream struct {
	io.ReadCloser
	unpin func()
	once  sync.Once
}

func (s *releaseStream) Close() error {
	var err error
	s.once.Do(func() {
		if s.unpin != nil {
			s.unpin()
		}
		err = s.ReadCloser.Close()
	})
	return err
}

// IntegrityIndex maintains a thread-safe registry of package version integrity digests.
type IntegrityIndex struct {
	mu      sync.RWMutex
	entries map[string]string // key: "pkg@version", value: integrity string
}

// NewIntegrityIndex creates an empty integrity index.
func NewIntegrityIndex() *IntegrityIndex {
	return &IntegrityIndex{
		entries: make(map[string]string),
	}
}

// Set records the expected integrity for a package version.
func (idx *IntegrityIndex) Set(pkg, version, integrity string) {
	if pkg == "" || version == "" || integrity == "" {
		return
	}
	idx.mu.Lock()
	defer idx.mu.Unlock()
	idx.entries[pkg+"@"+version] = integrity
}

// Get retrieves the recorded integrity for a package version, if known.
func (idx *IntegrityIndex) Get(pkg, version string) (string, bool) {
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	val, ok := idx.entries[pkg+"@"+version]
	return val, ok
}

// ResolveIntegrity implements IntegrityResolver on IntegrityIndex.
func (idx *IntegrityIndex) ResolveIntegrity(ctx context.Context, pkg, version string) (string, error) {
	if val, ok := idx.Get(pkg, version); ok {
		return val, nil
	}
	return "", fmt.Errorf("integrity not found in index for %s@%s", pkg, version)
}

// IntegrityResolver defines the interface for resolving expected package integrity.
type IntegrityResolver interface {
	ResolveIntegrity(ctx context.Context, pkg, version string) (string, error)
}

// IntegrityResolverFunc adapts a function to IntegrityResolver.
type IntegrityResolverFunc func(ctx context.Context, pkg, version string) (string, error)

func (f IntegrityResolverFunc) ResolveIntegrity(ctx context.Context, pkg, version string) (string, error) {
	return f(ctx, pkg, version)
}
