package quarantine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// errorAfterNReader reads up to n bytes then returns an error.
type errorAfterNReader struct {
	data []byte
	n    int
	read int
	err  error
}

func (r *errorAfterNReader) Read(p []byte) (int, error) {
	if r.read >= r.n {
		return 0, r.err
	}
	remaining := r.n - r.read
	toRead := len(p)
	if toRead > remaining {
		toRead = remaining
	}
	copy(p, r.data[r.read:r.read+toRead])
	r.read += toRead
	if r.read >= r.n {
		return toRead, r.err
	}
	return toRead, nil
}

// TestCrashRecovery_InterruptedQuarantineWritePurgesStagingAndLeavesStoreConsistent proves that
// when a quarantine write is interrupted (e.g. stream drops, cancelled context, abrupt crash),
// no partial or corrupted blob enters blobs/, the staging directory cleans up, and subsequent writes succeed.
func TestCrashRecovery_InterruptedQuarantineWritePurgesStagingAndLeavesStoreConsistent(t *testing.T) {
	tempDir := t.TempDir()
	meta := NewMemoryMetadataStore()
	store, err := NewDiskBlobStore(tempDir, DiskBudget{MaxBytes: 10 * 1024 * 1024}, meta)
	if err != nil {
		t.Fatalf("NewDiskBlobStore failed: %v", err)
	}

	payload := bytes.Repeat([]byte("CRASH_TEST_DATA_BLOB_STREAM"), 1000)
	key := "test-interrupted-blob-key"

	// 1. Interrupted write due to stream error
	streamErr := errors.New("simulated network connection drop mid-stream")
	faultyReader := &errorAfterNReader{
		data: payload,
		n:    len(payload) / 2,
		err:  streamErr,
	}

	ctx := context.Background()
	_, err = store.Put(ctx, key, faultyReader)
	if err == nil {
		t.Fatal("expected error during interrupted write, got nil")
	}
	if !errors.Is(err, streamErr) {
		t.Fatalf("expected streamErr in error, got: %v", err)
	}

	// 2. Assert: No blob in blobs/
	if store.Has(ctx, key) {
		t.Fatal("interrupted blob was stored in blobs directory!")
	}
	if _, err := os.Stat(store.BlobPath(key)); !os.IsNotExist(err) {
		t.Fatal("blob file exists on disk despite interrupted write")
	}

	// 3. Assert: Staging directory contains 0 dangling files
	stagingDir := filepath.Join(tempDir, "staging")
	entries, err := os.ReadDir(stagingDir)
	if err != nil {
		t.Fatalf("failed reading staging dir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected staging dir to have 0 files after failed write, found %d", len(entries))
	}

	// 4. Simulate process crash leaving a stale staging file (e.g. SIGKILL before defer runs)
	staleStagingPath := filepath.Join(stagingDir, "ingest_orphaned_by_sigkill.tmp")
	if err := os.WriteFile(staleStagingPath, []byte("garbage left by dead process"), 0o600); err != nil {
		t.Fatalf("failed writing stale staging file: %v", err)
	}

	// 5. Restart: NewDiskBlobStore must automatically clean up all stale staging files on startup
	store2, err := NewDiskBlobStore(tempDir, DiskBudget{MaxBytes: 10 * 1024 * 1024}, meta)
	if err != nil {
		t.Fatalf("NewDiskBlobStore restart failed: %v", err)
	}

	entriesAfterRestart, err := os.ReadDir(stagingDir)
	if err != nil {
		t.Fatalf("failed reading staging dir: %v", err)
	}
	if len(entriesAfterRestart) != 0 {
		t.Fatalf("expected 0 staging files after restart, found %d (stale files not cleaned up!)", len(entriesAfterRestart))
	}

	// 6. Complete clean write afterwards: succeeds normally
	cleanWritten, err := store2.Put(ctx, key, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("Put failed after restart recovery: %v", err)
	}
	if cleanWritten != int64(len(payload)) {
		t.Fatalf("written = %d, want %d", cleanWritten, len(payload))
	}

	// Verify content integrity
	rc, size, err := store2.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	defer rc.Close()
	if size != int64(len(payload)) {
		t.Fatalf("size = %d, want %d", size, len(payload))
	}
	delivered, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}
	if !bytes.Equal(delivered, payload) {
		t.Fatal("read bytes do not match expected payload")
	}
}
