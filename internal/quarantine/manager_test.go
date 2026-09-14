package quarantine

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"testing"
)

func TestQuarantine_DoubleIntegrityVerification_HappyPath(t *testing.T) {
	tempDir := t.TempDir()
	meta := NewMemoryMetadataStore()
	store, err := NewDiskBlobStore(tempDir, DiskBudget{MaxBytes: 10 * 1024 * 1024}, meta)
	if err != nil {
		t.Fatalf("NewDiskBlobStore failed: %v", err)
	}

	mgr, err := NewManager(Config{
		Store:    store,
		Metadata: meta,
		Limits:   DefaultArchiveLimits(),
	})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	tarballBytes := createTestTarball(t, map[string][]byte{
		"package/package.json": []byte(`{"name":"test-pkg","version":"1.0.0"}`),
	}, nil)

	h := sha512.Sum512(tarballBytes)
	declaredIntegrity := "sha512-" + base64.StdEncoding.EncodeToString(h[:])

	ctx := context.Background()

	// 1. Ingest into quarantine: FIRST INTEGRITY VERIFICATION
	entry, err := mgr.Ingest(ctx, "test-pkg", "1.0.0", declaredIntegrity, bytes.NewReader(tarballBytes))
	if err != nil {
		t.Fatalf("Ingest failed: %v", err)
	}
	if entry.Key == "" {
		t.Fatal("expected non-empty entry key")
	}

	// Verify entry is pinned during active inspection
	if !store.IsPinned(entry.Key) {
		t.Fatal("expected blob to be pinned during active inspection")
	}

	// 2. Safe static inspection
	inspection, err := mgr.Inspect(ctx, entry)
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}
	if inspection.EntryCount != 1 {
		t.Errorf("EntryCount = %d, want 1", inspection.EntryCount)
	}

	// Verify inspection pin was released
	if store.IsPinned(entry.Key) {
		t.Fatal("expected inspection pin to be released after Inspect()")
	}

	// 3. SECOND INTEGRITY VERIFICATION before release
	stream, size, err := mgr.VerifyAndRelease(ctx, entry.Key, declaredIntegrity)
	if err != nil {
		t.Fatalf("VerifyAndRelease failed: %v", err)
	}
	defer stream.Close()

	if size != int64(len(tarballBytes)) {
		t.Errorf("stream size = %d, want %d", size, len(tarballBytes))
	}

	// Verify blob is pinned during active release streaming
	if !store.IsPinned(entry.Key) {
		t.Fatal("expected blob to be pinned during active release streaming")
	}

	delivered, err := io.ReadAll(stream)
	if err != nil {
		t.Fatalf("failed reading release stream: %v", err)
	}
	if !bytes.Equal(delivered, tarballBytes) {
		t.Fatal("delivered bytes do not match original tarball bytes")
	}

	// Close stream and verify unpinned
	if err := stream.Close(); err != nil {
		t.Fatalf("stream.Close failed: %v", err)
	}
	if store.IsPinned(entry.Key) {
		t.Fatal("expected release pin to be released after stream.Close()")
	}
}

func TestQuarantine_BlobCorruptedBetweenVerificationsFailsSecondVerification(t *testing.T) {
	tempDir := t.TempDir()
	meta := NewMemoryMetadataStore()
	store, err := NewDiskBlobStore(tempDir, DiskBudget{MaxBytes: 10 * 1024 * 1024}, meta)
	if err != nil {
		t.Fatalf("NewDiskBlobStore failed: %v", err)
	}

	mgr, err := NewManager(Config{
		Store:    store,
		Metadata: meta,
		Limits:   DefaultArchiveLimits(),
	})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	tarballBytes := createTestTarball(t, map[string][]byte{
		"package/package.json": []byte(`{"name":"corruptible-pkg","version":"1.0.0"}`),
	}, nil)

	h := sha512.Sum512(tarballBytes)
	declaredIntegrity := "sha512-" + base64.StdEncoding.EncodeToString(h[:])

	ctx := context.Background()

	// 1. Ingest (First integrity verification passes)
	entry, err := mgr.Ingest(ctx, "corruptible-pkg", "1.0.0", declaredIntegrity, bytes.NewReader(tarballBytes))
	if err != nil {
		t.Fatalf("Ingest failed: %v", err)
	}

	// 2. Inspect (succeeds)
	_, err = mgr.Inspect(ctx, entry)
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}

	// 3. TAMPERING: Corrupt the blob on disk between inspection and release
	blobDiskPath := store.BlobPath(entry.Key)
	corruptedBytes := make([]byte, len(tarballBytes))
	copy(corruptedBytes, tarballBytes)
	corruptedBytes[len(corruptedBytes)-1] ^= 0xFF // flip bits at end of file

	if err := os.WriteFile(blobDiskPath, corruptedBytes, 0o600); err != nil {
		t.Fatalf("failed corrupting blob on disk: %v", err)
	}

	// 4. SECOND INTEGRITY VERIFICATION: MUST FAIL
	stream, _, err := mgr.VerifyAndRelease(ctx, entry.Key, declaredIntegrity)
	if err == nil {
		if stream != nil {
			_ = stream.Close()
		}
		t.Fatal("expected second integrity verification to fail for corrupted blob, got nil")
	}

	if !errors.Is(err, ErrIntegrityMismatchSecond) {
		t.Fatalf("expected ErrIntegrityMismatchSecond, got: %v", err)
	}

	if stream != nil {
		t.Fatal("stream must be nil when second verification fails")
	}

	// Verify metadata reflects Blocked status
	m, err := meta.Get(ctx, entry.Key)
	if err != nil {
		t.Fatalf("failed reading metadata: %v", err)
	}
	if m.Status != StatusBlocked {
		t.Errorf("expected metadata status %q, got %q", StatusBlocked, m.Status)
	}
}

func TestQuarantine_FirstVerificationMismatchRejectsImmediately(t *testing.T) {
	tempDir := t.TempDir()
	meta := NewMemoryMetadataStore()
	store, err := NewDiskBlobStore(tempDir, DiskBudget{MaxBytes: 10 * 1024 * 1024}, meta)
	if err != nil {
		t.Fatalf("NewDiskBlobStore failed: %v", err)
	}

	mgr, err := NewManager(Config{
		Store:    store,
		Metadata: meta,
		Limits:   DefaultArchiveLimits(),
	})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	tarballBytes := createTestTarball(t, map[string][]byte{
		"package/package.json": []byte(`{"name":"bad-integrity-pkg"}`),
	}, nil)

	// Declare a digest that does not match the actual tarball bytes
	fakeDigest := "sha512-" + base64.StdEncoding.EncodeToString(make([]byte, 64))

	ctx := context.Background()

	// Ingest with mismatched declared integrity: MUST FAIL at first verification
	_, err = mgr.Ingest(ctx, "bad-integrity-pkg", "1.0.0", fakeDigest, bytes.NewReader(tarballBytes))
	if err == nil {
		t.Fatal("expected ErrIntegrityMismatch, got nil")
	}
	if !errors.Is(err, ErrIntegrityMismatch) {
		t.Fatalf("expected ErrIntegrityMismatch, got: %v", err)
	}

	// Assert: blob was NEVER stored into blobs directory
	parsed, _ := ParseDigest(fakeDigest)
	if store.Has(ctx, parsed.Key()) {
		t.Fatal("mismatched blob was improperly stored in blobstore")
	}
}
