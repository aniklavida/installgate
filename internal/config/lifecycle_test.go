package config

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aniklavida/installgate/internal/evidence"
)

func TestLifecycleManager_RefuseEnableWhenGatewayNotRunning(t *testing.T) {
	tempDir := t.TempDir()
	dataDir := filepath.Join(tempDir, "data")
	npmrcPath := filepath.Join(tempDir, ".npmrc")

	mgr, err := NewLifecycleManager(
		WithDataDir(dataDir),
		WithNpmrcPath(npmrcPath),
		WithGatewayURL("http://127.0.0.1:8765"),
		WithHealthChecker(func(ctx context.Context, gatewayURL string) (*HealthResponse, error) {
			return nil, errors.New("connection refused")
		}),
	)
	if err != nil {
		t.Fatal(err)
	}

	err = mgr.EnableNpm(context.Background())
	if err == nil {
		t.Fatal("expected error enabling npm when gateway is not running, got nil")
	}

	if !strings.Contains(err.Error(), "gateway is not running or not ready") {
		t.Errorf("unexpected error message: %v", err)
	}

	// Verify .npmrc was NEVER created or touched
	if _, err := os.Stat(npmrcPath); !os.IsNotExist(err) {
		t.Errorf(".npmrc was created despite refusal")
	}
}

func TestLifecycleManager_FullEnableDisableFlow(t *testing.T) {
	tempDir := t.TempDir()
	dataDir := filepath.Join(tempDir, "data")
	npmrcPath := filepath.Join(tempDir, ".npmrc")

	originalBytes := []byte("registry=https://registry.npmjs.org/\naudit=false\n")
	if err := os.WriteFile(npmrcPath, originalBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	cacheStats := evidence.CacheStats{
		TotalEntries: 5,
		FreshEntries: 4,
		StaleEntries: 1,
	}

	mgr, err := NewLifecycleManager(
		WithDataDir(dataDir),
		WithNpmrcPath(npmrcPath),
		WithGatewayURL("http://127.0.0.1:8765"),
		WithHealthChecker(func(ctx context.Context, gatewayURL string) (*HealthResponse, error) {
			return &HealthResponse{
				Status: "ok",
				Ready:  true,
				Cache:  cacheStats,
			}, nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	// Initial status
	st, err := mgr.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !st.GatewayRunning {
		t.Errorf("expected GatewayRunning=true")
	}
	if st.NpmEnabled {
		t.Errorf("expected NpmEnabled=false before enable")
	}
	if st.CacheStats.TotalEntries != 5 || st.CacheStats.FreshEntries != 4 {
		t.Errorf("unexpected cache stats: %+v", st.CacheStats)
	}

	// Enable
	if err := mgr.EnableNpm(ctx); err != nil {
		t.Fatalf("EnableNpm failed: %v", err)
	}

	// Status after enable
	st, err = mgr.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !st.NpmEnabled {
		t.Errorf("expected NpmEnabled=true after enable")
	}
	if st.ActiveRegistry != "http://127.0.0.1:8765/" {
		t.Errorf("expected active registry to be gateway URL, got %s", st.ActiveRegistry)
	}

	// Disable
	if err := mgr.DisableNpm(ctx); err != nil {
		t.Fatalf("DisableNpm failed: %v", err)
	}

	// Status after disable
	st, err = mgr.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.NpmEnabled {
		t.Errorf("expected NpmEnabled=false after disable")
	}

	// Verify exact byte-for-byte restoration
	restoredBytes, err := os.ReadFile(npmrcPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restoredBytes, originalBytes) {
		t.Fatalf("restoration not byte-for-byte identical:\ngot:\n%s\nwant:\n%s", string(restoredBytes), string(originalBytes))
	}
}

func TestLifecycleManager_StatusWhenGatewayStopped(t *testing.T) {
	tempDir := t.TempDir()
	dataDir := filepath.Join(tempDir, "data")
	npmrcPath := filepath.Join(tempDir, ".npmrc")

	mgr, err := NewLifecycleManager(
		WithDataDir(dataDir),
		WithNpmrcPath(npmrcPath),
		WithGatewayURL("http://127.0.0.1:8765"),
		WithHealthChecker(func(ctx context.Context, gatewayURL string) (*HealthResponse, error) {
			return nil, errors.New("connection refused")
		}),
	)
	if err != nil {
		t.Fatal(err)
	}

	st, err := mgr.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.GatewayRunning {
		t.Errorf("expected GatewayRunning=false")
	}
	if st.CacheStats.TotalEntries != 0 {
		t.Errorf("expected 0 cache entries when stopped, got %d", st.CacheStats.TotalEntries)
	}
}
