package quarantine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type errReader struct {
	data  []byte
	limit int
	read  int
}

func (r *errReader) Read(p []byte) (int, error) {
	if r.read >= r.limit {
		return 0, errors.New("simulated network disconnect during tarball fetch")
	}
	remaining := r.limit - r.read
	toRead := len(p)
	if toRead > remaining {
		toRead = remaining
	}
	copy(p, r.data[r.read:r.read+toRead])
	r.read += toRead
	if r.read >= r.limit {
		return toRead, errors.New("simulated network disconnect during tarball fetch")
	}
	return toRead, nil
}

func makeTestBlob(content []byte) (string, ParsedDigest) {
	h := sha256.Sum256(content)
	key := "sha256-" + hex.EncodeToString(h[:])
	d, _ := ParseDigest(key)
	return key, d
}

func TestBlobStore_ContentAddressedDeduplication(t *testing.T) {
	tempDir := t.TempDir()
	meta := NewMemoryMetadataStore()
	store, err := NewDiskBlobStore(tempDir, DiskBudget{MaxBytes: 10 * 1024 * 1024}, meta)
	if err != nil {
		t.Fatalf("NewDiskBlobStore failed: %v", err)
	}

	content := []byte("identical package bytes fetched multiple times")
	key, digest := makeTestBlob(content)

	ctx := context.Background()

	// First Put
	size1, err := store.PutVerified(ctx, key, bytes.NewReader(content), digest)
	if err != nil {
		t.Fatalf("first PutVerified failed: %v", err)
	}
	if size1 != int64(len(content)) {
		t.Errorf("size1 = %d, want %d", size1, len(content))
	}

	initialTotal := store.TotalBytes()
	if initialTotal != int64(len(content)) {
		t.Errorf("initial TotalBytes = %d, want %d", initialTotal, len(content))
	}

	// Second Put with identical content
	size2, err := store.PutVerified(ctx, key, bytes.NewReader(content), digest)
	if err != nil {
		t.Fatalf("second PutVerified failed: %v", err)
	}
	if size2 != int64(len(content)) {
		t.Errorf("size2 = %d, want %d", size2, len(content))
	}

	// Must occupy exactly one entry and not duplicate bytes on disk
	if store.TotalBytes() != initialTotal {
		t.Errorf("TotalBytes after duplicate Put = %d, want %d", store.TotalBytes(), initialTotal)
	}

	entries, err := os.ReadDir(filepath.Join(tempDir, "blobs"))
	if err != nil {
		t.Fatalf("failed reading blobs directory: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 file in blobs directory, found %d", len(entries))
	}
}

func TestBlobStore_InterruptedWriteLeavesNoAddressableEntry(t *testing.T) {
	tempDir := t.TempDir()
	meta := NewMemoryMetadataStore()
	store, err := NewDiskBlobStore(tempDir, DiskBudget{MaxBytes: 10 * 1024 * 1024}, meta)
	if err != nil {
		t.Fatalf("NewDiskBlobStore failed: %v", err)
	}

	fullContent := []byte("large payload that will be cut off mid-stream by network failure")
	key, digest := makeTestBlob(fullContent)

	// Reader cuts off after 20 bytes with an error
	badReader := &errReader{
		data:  fullContent,
		limit: 20,
	}

	ctx := context.Background()
	_, err = store.PutVerified(ctx, key, badReader, digest)
	if err == nil {
		t.Fatal("expected error from interrupted write, got nil")
	}

	// Assert: partially written blob is NEVER addressable
	if store.Has(ctx, key) {
		t.Error("store.Has reported true for interrupted write")
	}

	_, _, getErr := store.Get(ctx, key)
	if !errors.Is(getErr, ErrBlobNotFound) && !os.IsNotExist(getErr) {
		t.Errorf("store.Get expected not found error, got: %v", getErr)
	}

	// Assert: blobs directory contains no entry
	blobPath := store.BlobPath(key)
	if _, err := os.Stat(blobPath); err == nil {
		t.Errorf("blob file exists at %s for interrupted write", blobPath)
	}

	// Assert: staging directory leaves no leftover temporary file
	stagingEntries, err := os.ReadDir(filepath.Join(tempDir, "staging"))
	if err != nil {
		t.Fatalf("failed reading staging dir: %v", err)
	}
	if len(stagingEntries) != 0 {
		t.Errorf("expected staging directory to be empty, found %d files", len(stagingEntries))
	}
}

func TestBlobStore_SizeBudgetAndEviction(t *testing.T) {
	tempDir := t.TempDir()
	meta := NewMemoryMetadataStore()
	// Budget: exactly 1500 bytes
	store, err := NewDiskBlobStore(tempDir, DiskBudget{MaxBytes: 1500}, meta)
	if err != nil {
		t.Fatalf("NewDiskBlobStore failed: %v", err)
	}

	ctx := context.Background()

	// Blob 1: 500 bytes (oldest)
	content1 := bytes.Repeat([]byte("A"), 500)
	key1, digest1 := makeTestBlob(content1)
	t0 := time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC)
	if _, err := store.PutVerified(ctx, key1, bytes.NewReader(content1), digest1); err != nil {
		t.Fatalf("PutVerified blob 1 failed: %v", err)
	}
	_ = meta.Put(ctx, BlobMetadata{Digest: key1, Size: 500, LastAccessedAt: t0, CreatedAt: t0})

	// Blob 2: 600 bytes (middle)
	content2 := bytes.Repeat([]byte("B"), 600)
	key2, digest2 := makeTestBlob(content2)
	t1 := time.Date(2026, 9, 15, 11, 0, 0, 0, time.UTC)
	if _, err := store.PutVerified(ctx, key2, bytes.NewReader(content2), digest2); err != nil {
		t.Fatalf("PutVerified blob 2 failed: %v", err)
	}
	_ = meta.Put(ctx, BlobMetadata{Digest: key2, Size: 600, LastAccessedAt: t1, CreatedAt: t1})

	// Total is now 1100 / 1500 bytes
	if store.TotalBytes() != 1100 {
		t.Fatalf("total bytes = %d, want 1100", store.TotalBytes())
	}

	// Blob 3: 600 bytes. Adding this exceeds 1500 (1100 + 600 = 1700 > 1500).
	// Eviction must trigger and evict Blob 1 (oldest accessed).
	content3 := bytes.Repeat([]byte("C"), 600)
	key3, digest3 := makeTestBlob(content3)
	t2 := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)

	if _, err := store.PutVerified(ctx, key3, bytes.NewReader(content3), digest3); err != nil {
		t.Fatalf("PutVerified blob 3 failed: %v", err)
	}
	_ = meta.Put(ctx, BlobMetadata{Digest: key3, Size: 600, LastAccessedAt: t2, CreatedAt: t2})

	// Blob 1 must have been evicted
	if store.Has(ctx, key1) {
		t.Errorf("expected Blob 1 to be evicted, but it is still present")
	}
	// Blobs 2 and 3 must remain
	if !store.Has(ctx, key2) {
		t.Errorf("expected Blob 2 to remain, but it was evicted")
	}
	if !store.Has(ctx, key3) {
		t.Errorf("expected Blob 3 to be present")
	}
	if store.TotalBytes() > 1500 {
		t.Errorf("TotalBytes = %d, exceeds budget 1500", store.TotalBytes())
	}
}

func TestBlobStore_EvictionPressureDuringActiveInspection(t *testing.T) {
	tempDir := t.TempDir()
	meta := NewMemoryMetadataStore()
	// Budget: 1000 bytes
	store, err := NewDiskBlobStore(tempDir, DiskBudget{MaxBytes: 1000}, meta)
	if err != nil {
		t.Fatalf("NewDiskBlobStore failed: %v", err)
	}

	ctx := context.Background()

	// Blob 1: 600 bytes
	content1 := bytes.Repeat([]byte("X"), 600)
	key1, digest1 := makeTestBlob(content1)
	t0 := time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC)
	if _, err := store.PutVerified(ctx, key1, bytes.NewReader(content1), digest1); err != nil {
		t.Fatalf("PutVerified blob 1 failed: %v", err)
	}
	_ = meta.Put(ctx, BlobMetadata{Digest: key1, Size: 600, LastAccessedAt: t0, CreatedAt: t0})

	// ACTIVE INSPECTION BEGINS: Pin Blob 1
	unpinInspection, err := store.Pin(key1)
	if err != nil {
		t.Fatalf("failed pinning Blob 1 for inspection: %v", err)
	}

	// Incoming Blob 2: 500 bytes. Total would be 1100 > 1000.
	// Eviction pressure arrives during active inspection of Blob 1.
	// Blob 1 is pinned and CANNOT be evicted.
	content2 := bytes.Repeat([]byte("Y"), 500)
	key2, digest2 := makeTestBlob(content2)

	_, err = store.PutVerified(ctx, key2, bytes.NewReader(content2), digest2)
	if err == nil {
		t.Fatal("expected ErrBudgetExceeded because active blob cannot be evicted, got nil")
	}
	if !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("expected ErrBudgetExceeded, got: %v", err)
	}

	// Assert: Blob 1 remains completely intact and present
	if !store.Has(ctx, key1) {
		t.Fatal("Blob 1 was improperly evicted during active inspection!")
	}

	// ACTIVE INSPECTION CONCLUDES: Unpin Blob 1
	unpinInspection()

	// Now that inspection is finished and Blob 1 is unpinned, eviction pressure can succeed
	_, err = store.PutVerified(ctx, key2, bytes.NewReader(content2), digest2)
	if err != nil {
		t.Fatalf("expected PutVerified to succeed after unpin, got: %v", err)
	}

	// Blob 1 should now be evicted to accommodate Blob 2
	if store.Has(ctx, key1) {
		t.Errorf("expected Blob 1 to be evicted after unpin")
	}
	if !store.Has(ctx, key2) {
		t.Errorf("expected Blob 2 to be stored")
	}
}
