package compat

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aniklavida/installgate/internal/config"
	"github.com/aniklavida/installgate/internal/quarantine"
)

// TestWindowsConfig_LineEndingsAndPaths proves that configuration rewriting
// respects Windows CRLF line endings and restores them byte-for-byte.
func TestWindowsConfig_LineEndingsAndPaths(t *testing.T) {
	tempDir := t.TempDir()
	dataDir := filepath.Join(tempDir, "data")
	npmrcPath := filepath.Join(tempDir, ".npmrc")

	// 1. Create .npmrc with Windows CRLF line endings
	crlfContent := []byte("registry=https://registry.npmjs.org/\r\naudit=false\r\nsave-exact=true\r\n")
	if err := os.WriteFile(npmrcPath, crlfContent, 0o644); err != nil {
		t.Fatalf("failed creating Windows .npmrc: %v", err)
	}

	mgr, err := config.NewLifecycleManager(
		config.WithDataDir(dataDir),
		config.WithNpmrcPath(npmrcPath),
		config.WithGatewayURL("http://127.0.0.1:8765"),
		config.WithHealthChecker(func(ctx context.Context, gatewayURL string) (*config.HealthResponse, error) {
			return &config.HealthResponse{Status: "ok", Ready: true}, nil
		}),
	)
	if err != nil {
		t.Fatalf("failed initializing LifecycleManager: %v", err)
	}

	ctx := context.Background()

	// 2. Enable: must preserve CRLF line endings
	if err := mgr.EnableNpm(ctx); err != nil {
		t.Fatalf("EnableNpm failed: %v", err)
	}

	enabledData, err := os.ReadFile(npmrcPath)
	if err != nil {
		t.Fatalf("failed reading enabled .npmrc: %v", err)
	}

	if !bytes.Contains(enabledData, []byte("\r\n")) {
		t.Errorf("enabled .npmrc lost Windows CRLF line endings")
	}
	if !bytes.Contains(enabledData, []byte("registry=http://127.0.0.1:8765/\r\n")) {
		t.Errorf("enabled .npmrc missing gateway registry line with CRLF: %s", string(enabledData))
	}

	// 3. Disable: must restore original content byte-for-byte
	if err := mgr.DisableNpm(ctx); err != nil {
		t.Fatalf("DisableNpm failed: %v", err)
	}

	restoredData, err := os.ReadFile(npmrcPath)
	if err != nil {
		t.Fatalf("failed reading restored .npmrc: %v", err)
	}

	if !bytes.Equal(restoredData, crlfContent) {
		t.Fatalf("restored .npmrc is not byte-identical to original Windows CRLF content:\ngot  %q\nwant %q", string(restoredData), string(crlfContent))
	}
}

// TestWindowsConfig_FileLockingDuringTransaction verifies that staging and committing
// close all file handles properly so Windows file-locking doesn't block rename or cleanup.
func TestWindowsConfig_FileLockingDuringTransaction(t *testing.T) {
	tempDir := t.TempDir()
	dataDir := filepath.Join(tempDir, "data")
	npmrcPath := filepath.Join(tempDir, ".npmrc")

	mgr, err := config.NewLifecycleManager(
		config.WithDataDir(dataDir),
		config.WithNpmrcPath(npmrcPath),
		config.WithGatewayURL("http://127.0.0.1:8765"),
		config.WithHealthChecker(func(ctx context.Context, gatewayURL string) (*config.HealthResponse, error) {
			return &config.HealthResponse{Status: "ok", Ready: true}, nil
		}),
	)
	if err != nil {
		t.Fatalf("failed initializing LifecycleManager: %v", err)
	}

	ctx := context.Background()

	// Rapid sequential enable and disable cycles to detect any leaked file descriptors
	for i := 0; i < 5; i++ {
		if err := mgr.EnableNpm(ctx); err != nil {
			t.Fatalf("cycle %d: EnableNpm failed: %v", i, err)
		}
		if err := mgr.DisableNpm(ctx); err != nil {
			t.Fatalf("cycle %d: DisableNpm failed: %v", i, err)
		}
	}
}

// TestWindowsQuarantine_BackslashesAndPaths asserts that Windows-style path separators
// in tarball entries are normalized and cannot escape the extraction root.
func TestWindowsQuarantine_BackslashesAndPaths(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	// Valid entry with backslashes
	hdr := &tar.Header{
		Name:    `package\lib\index.js`,
		Mode:    0o644,
		Size:    int64(len("module.exports = {};")),
		ModTime: time.Now(),
	}
	_ = tw.WriteHeader(hdr)
	_, _ = tw.Write([]byte("module.exports = {};"))

	// Traversal entry with backslashes
	hdrBad := &tar.Header{
		Name:    `package\..\..\outside.txt`,
		Mode:    0o644,
		Size:    int64(len("escaped")),
		ModTime: time.Now(),
	}
	_ = tw.WriteHeader(hdrBad)
	_, _ = tw.Write([]byte("escaped"))

	_ = tw.Close()
	_ = gw.Close()

	limits := quarantine.DefaultArchiveLimits()
	_, err := quarantine.InspectArchive(context.Background(), bytes.NewReader(buf.Bytes()), limits)
	if err == nil {
		t.Fatal("expected InspectArchive to reject Windows backslash traversal, got nil")
	}
	if !errors.Is(err, quarantine.ErrArchivePathTraversal) {
		t.Errorf("expected ErrArchivePathTraversal, got: %v", err)
	}
}

// TestWindowsQuarantine_NoDescriptorLeaks verifies that reading and verifying quarantined blobs
// releases open file descriptors immediately to prevent file lock contention.
func TestWindowsQuarantine_NoDescriptorLeaks(t *testing.T) {
	h := NewTestHarness(t)

	// Ingest and release multiple times
	for i := 0; i < 5; i++ {
		tarResp, err := http.Get(h.GatewayURL() + "/fixture-unscoped/-/fixture-unscoped-1.0.0.tgz")
		if err != nil {
			t.Fatalf("iteration %d: GET tarball failed: %v", i, err)
		}
		if tarResp.StatusCode != http.StatusOK {
			t.Fatalf("iteration %d: expected 200 OK, got %d", i, tarResp.StatusCode)
		}
		_ = tarResp.Body.Close()
	}
}
