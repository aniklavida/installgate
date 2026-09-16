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

// TestIntegrityAdversarial_FirstVerificationTamperRejection proves that any discrepancy
// between declared integrity and actual tarball bytes is rejected at initial ingestion,
// purging staging files and never storing unverified bytes.
func TestIntegrityAdversarial_FirstVerificationTamperRejection(t *testing.T) {
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

	validTarball := createTestTarball(t, map[string][]byte{
		"package/package.json": []byte(`{"name":"tamper-first-test","version":"1.0.0"}`),
	}, nil)

	h := sha512.Sum512(validTarball)
	validIntegrity := "sha512-" + base64.StdEncoding.EncodeToString(h[:])

	// Tampered tarball bytes (bit flipped)
	tamperedTarball := make([]byte, len(validTarball))
	copy(tamperedTarball, validTarball)
	tamperedTarball[len(tamperedTarball)/2] ^= 0xAA

	ctx := context.Background()

	// Ingest tampered tarball with validIntegrity: MUST fail at first verification
	entry, err := mgr.Ingest(ctx, "tamper-first-test", "1.0.0", validIntegrity, bytes.NewReader(tamperedTarball))
	if err == nil {
		t.Fatal("expected ErrIntegrityMismatch during ingestion, got nil")
	}
	if !errors.Is(err, ErrIntegrityMismatch) {
		t.Fatalf("expected ErrIntegrityMismatch, got: %v", err)
	}
	if entry != nil {
		t.Fatal("entry must be nil when first verification fails")
	}

	// Verify no blob was committed to store
	parsed, _ := ParseDigest(validIntegrity)
	if store.Has(ctx, parsed.Key()) {
		t.Fatal("unverified/tampered blob was stored in store!")
	}

	// Verify metadata reflects blocked status
	blobMeta, err := meta.Get(ctx, parsed.Key())
	if err != nil {
		t.Fatalf("failed retrieving metadata: %v", err)
	}
	if blobMeta.Status != StatusBlocked {
		t.Fatalf("expected status %q, got %q", StatusBlocked, blobMeta.Status)
	}
}

// TestIntegrityAdversarial_MiddleTamperingBetweenChecksFailsSecondVerification proves that
// any tampering occurring on disk between inspection and release is caught by the second check.
func TestIntegrityAdversarial_MiddleTamperingBetweenChecksFailsSecondVerification(t *testing.T) {
	tamperScenarios := []struct {
		name   string
		tamper func([]byte) []byte
	}{
		{
			name: "BitFlipAtHeader",
			tamper: func(data []byte) []byte {
				c := make([]byte, len(data))
				copy(c, data)
				c[0] ^= 0x01
				return c
			},
		},
		{
			name: "BitFlipAtMiddle",
			tamper: func(data []byte) []byte {
				c := make([]byte, len(data))
				copy(c, data)
				c[len(c)/2] ^= 0x80
				return c
			},
		},
		{
			name: "BitFlipAtFooter",
			tamper: func(data []byte) []byte {
				c := make([]byte, len(data))
				copy(c, data)
				c[len(c)-1] ^= 0xFF
				return c
			},
		},
		{
			name: "AppendedTrailingByte",
			tamper: func(data []byte) []byte {
				return append(append([]byte{}, data...), 0x00)
			},
		},
		{
			name: "TruncatedByTenBytes",
			tamper: func(data []byte) []byte {
				if len(data) > 10 {
					return data[:len(data)-10]
				}
				return data[:len(data)/2]
			},
		},
		{
			name: "CompletelyReplacedPayload",
			tamper: func(data []byte) []byte {
				return bytes.Repeat([]byte("EVIL_PAYLOAD"), 10)
			},
		},
	}

	for _, sc := range tamperScenarios {
		t.Run(sc.name, func(t *testing.T) {
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

			validTarball := createTestTarball(t, map[string][]byte{
				"package/package.json": []byte(`{"name":"middle-tamper-pkg","version":"1.0.0"}`),
				"package/index.js":     []byte("module.exports = 42;\n"),
			}, nil)

			h := sha512.Sum512(validTarball)
			declaredIntegrity := "sha512-" + base64.StdEncoding.EncodeToString(h[:])

			ctx := context.Background()

			// Step 1: Ingest into quarantine (first integrity verification passes)
			entry, err := mgr.Ingest(ctx, "middle-tamper-pkg", "1.0.0", declaredIntegrity, bytes.NewReader(validTarball))
			if err != nil {
				t.Fatalf("Ingest failed: %v", err)
			}

			// Step 2: Safe static inspection passes
			inspection, err := mgr.Inspect(ctx, entry)
			if err != nil {
				t.Fatalf("Inspect failed: %v", err)
			}
			if inspection.EntryCount != 2 {
				t.Fatalf("EntryCount = %d, want 2", inspection.EntryCount)
			}

			// Step 3: TAMPERING - apply middle tampering directly to stored blob on disk
			blobDiskPath := store.BlobPath(entry.Key)
			tamperedBytes := sc.tamper(validTarball)
			if err := os.WriteFile(blobDiskPath, tamperedBytes, 0o600); err != nil {
				t.Fatalf("failed applying middle tampering to blob: %v", err)
			}

			// Step 4: SECOND INTEGRITY VERIFICATION before release - MUST FAIL
			stream, size, err := mgr.VerifyAndRelease(ctx, entry.Key, declaredIntegrity)
			if err == nil {
				if stream != nil {
					_ = stream.Close()
				}
				t.Fatalf("[%s] expected ErrIntegrityMismatchSecond, got nil error (released size: %d)", sc.name, size)
			}

			if !errors.Is(err, ErrIntegrityMismatchSecond) {
				t.Fatalf("[%s] expected ErrIntegrityMismatchSecond, got: %v", sc.name, err)
			}

			if stream != nil {
				t.Fatalf("[%s] stream must be nil when second verification fails", sc.name)
			}

			// Step 5: Verify status in metadata is updated to StatusBlocked
			m, err := meta.Get(ctx, entry.Key)
			if err != nil {
				t.Fatalf("failed retrieving metadata: %v", err)
			}
			if m.Status != StatusBlocked {
				t.Fatalf("[%s] expected metadata status %q, got %q", sc.name, StatusBlocked, m.Status)
			}

			// Step 6: Verify blob is unpinned and not held open
			if store.IsPinned(entry.Key) {
				t.Fatalf("[%s] blob remains pinned after failed release", sc.name)
			}
		})
	}
}

// TestIntegrityAdversarial_PinnedLeasePreventsEvictionDuringInspectionAndRelease asserts
// that an active inspection lease or active release streaming lease strictly prevents eviction.
func TestIntegrityAdversarial_PinnedLeasePreventsEvictionDuringInspectionAndRelease(t *testing.T) {
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

	validTarball := createTestTarball(t, map[string][]byte{
		"package/package.json": []byte(`{"name":"pin-test","version":"1.0.0"}`),
	}, nil)

	h := sha512.Sum512(validTarball)
	declaredIntegrity := "sha512-" + base64.StdEncoding.EncodeToString(h[:])

	ctx := context.Background()

	// Ingest: blob is pinned for active inspection
	entry, err := mgr.Ingest(ctx, "pin-test", "1.0.0", declaredIntegrity, bytes.NewReader(validTarball))
	if err != nil {
		t.Fatalf("Ingest failed: %v", err)
	}

	// Attempting to delete a pinned blob must fail with ErrBlobPinned
	if err := store.Delete(ctx, entry.Key); !errors.Is(err, ErrBlobPinned) {
		t.Fatalf("expected ErrBlobPinned during active inspection, got: %v", err)
	}

	// Complete inspection -> inspection pin released
	_, err = mgr.Inspect(ctx, entry)
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}

	// Verify unpinned after inspection
	if store.IsPinned(entry.Key) {
		t.Fatal("expected blob to be unpinned after Inspect()")
	}

	// Begin release stream: blob is pinned for release
	stream, _, err := mgr.VerifyAndRelease(ctx, entry.Key, declaredIntegrity)
	if err != nil {
		t.Fatalf("VerifyAndRelease failed: %v", err)
	}

	// Attempting to delete while stream is open must fail
	if err := store.Delete(ctx, entry.Key); !errors.Is(err, ErrBlobPinned) {
		t.Fatalf("expected ErrBlobPinned during active release stream, got: %v", err)
	}

	// Consume and close stream
	_, _ = io.ReadAll(stream)
	if err := stream.Close(); err != nil {
		t.Fatalf("stream.Close failed: %v", err)
	}

	// Verify unpinned after stream.Close()
	if store.IsPinned(entry.Key) {
		t.Fatal("expected blob to be unpinned after stream.Close()")
	}

	// Now deletion succeeds cleanly
	if err := store.Delete(ctx, entry.Key); err != nil {
		t.Fatalf("Delete failed after unpin: %v", err)
	}
}
