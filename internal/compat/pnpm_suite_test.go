package compat

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func skipIfPnpmMissing(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("pnpm"); err != nil {
		t.Skip("pnpm binary not found on this host; skipping local pnpm test; verified in CI runner")
	}
}

func setupPnpmWorkspace(t *testing.T, gatewayURL string, pkgJSONContent string) string {
	t.Helper()
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkgJSONContent), 0o644); err != nil {
		t.Fatalf("failed writing package.json: %v", err)
	}

	npmrcContent := fmt.Sprintf("registry=%s/\nstore-dir=%s\n", gatewayURL, filepath.Join(dir, ".pnpm-store"))
	if err := os.WriteFile(filepath.Join(dir, ".npmrc"), []byte(npmrcContent), 0o644); err != nil {
		t.Fatalf("failed writing .npmrc: %v", err)
	}

	return dir
}

func runPnpm(ctx context.Context, dir, gatewayURL string, args ...string) (string, string, int, error) {
	env := IsolatedClientEnv(dir, gatewayURL)
	return RunCmd(ctx, dir, env, "pnpm", args...)
}

func TestPnpm_ScopedAndUnscopedInstall(t *testing.T) {
	skipIfPnpmMissing(t)
	h := NewTestHarness(t)

	pkgJSON := `{
  "name": "test-pnpm-scoped-unscoped",
  "version": "1.0.0",
  "dependencies": {
    "fixture-unscoped": "1.0.0",
    "@testscope/fixture-scoped": "1.0.0"
  }
}
`
	workDir := setupPnpmWorkspace(t, h.GatewayURL(), pkgJSON)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	stdout, stderr, code, err := runPnpm(ctx, workDir, h.GatewayURL(), "install")
	if err != nil || code != 0 {
		t.Fatalf("pnpm install failed (code %d): err=%v\nstdout: %s\nstderr: %s", code, err, stdout, stderr)
	}

	AssertInstalledPackage(t, workDir, "fixture-unscoped", "1.0.0")
	AssertInstalledPackage(t, workDir, "@testscope/fixture-scoped", "1.0.0")

	// Verify pnpm-lock.yaml was created and references packages
	lockData, err := os.ReadFile(filepath.Join(workDir, "pnpm-lock.yaml"))
	if err != nil {
		t.Fatalf("failed reading pnpm-lock.yaml: %v", err)
	}
	lockStr := string(lockData)
	if !strings.Contains(lockStr, "fixture-unscoped") {
		t.Errorf("pnpm-lock.yaml does not contain fixture-unscoped")
	}
}

func TestPnpm_PeerAndOptionalDependencies(t *testing.T) {
	skipIfPnpmMissing(t)
	h := NewTestHarness(t)

	pkgJSON := `{
  "name": "test-pnpm-peer-optional",
  "version": "1.0.0",
  "dependencies": {
    "fixture-peer": "1.0.0",
    "fixture-optional": "1.0.0"
  }
}
`
	workDir := setupPnpmWorkspace(t, h.GatewayURL(), pkgJSON)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	stdout, stderr, code, err := runPnpm(ctx, workDir, h.GatewayURL(), "install")
	if err != nil || code != 0 {
		t.Fatalf("pnpm install failed (code %d): err=%v\nstdout: %s\nstderr: %s", code, err, stdout, stderr)
	}

	AssertInstalledPackage(t, workDir, "fixture-peer", "1.0.0")
	AssertInstalledPackage(t, workDir, "fixture-optional", "1.0.0")
	AssertInstalledPackage(t, workDir, "fixture-unscoped", "1.0.0")
}

func TestPnpm_LockfileDrivenInstall(t *testing.T) {
	skipIfPnpmMissing(t)
	h := NewTestHarness(t)

	pkgJSON := `{
  "name": "test-pnpm-lockfile",
  "version": "1.0.0",
  "dependencies": {
    "fixture-unscoped": "1.0.0"
  }
}
`
	workDir := setupPnpmWorkspace(t, h.GatewayURL(), pkgJSON)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Initial install
	stdout, stderr, code, err := runPnpm(ctx, workDir, h.GatewayURL(), "install")
	if err != nil || code != 0 {
		t.Fatalf("initial pnpm install failed: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}

	// Remove node_modules
	_ = os.RemoveAll(filepath.Join(workDir, "node_modules"))

	// Frozen lockfile install
	stdout, stderr, code, err = runPnpm(ctx, workDir, h.GatewayURL(), "install", "--frozen-lockfile")
	if err != nil || code != 0 {
		t.Fatalf("pnpm install --frozen-lockfile failed: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}

	AssertInstalledPackage(t, workDir, "fixture-unscoped", "1.0.0")
}

func TestPnpm_Workspaces(t *testing.T) {
	skipIfPnpmMissing(t)
	h := NewTestHarness(t)

	dir := t.TempDir()
	rootPkgJSON := `{
  "name": "test-pnpm-workspaces-root",
  "private": true
}
`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(rootPkgJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	workspaceYAML := "packages:\n  - 'packages/*'\n"
	if err := os.WriteFile(filepath.Join(dir, "pnpm-workspace.yaml"), []byte(workspaceYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	npmrcContent := fmt.Sprintf("registry=%s/\nstore-dir=%s\n", h.GatewayURL(), filepath.Join(dir, ".pnpm-store"))
	if err := os.WriteFile(filepath.Join(dir, ".npmrc"), []byte(npmrcContent), 0o644); err != nil {
		t.Fatal(err)
	}

	appDir := filepath.Join(dir, "packages", "app")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	appPkgJSON := `{
  "name": "@workspace/app",
  "version": "1.0.0",
  "dependencies": {
    "fixture-unscoped": "1.0.0"
  }
}
`
	if err := os.WriteFile(filepath.Join(appDir, "package.json"), []byte(appPkgJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	stdout, stderr, code, err := runPnpm(ctx, dir, h.GatewayURL(), "install")
	if err != nil || code != 0 {
		t.Fatalf("pnpm install in workspace failed: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}

	// Verify package is present in workspace package node_modules or root
	pkgInstalled := false
	if _, err := os.Stat(filepath.Join(appDir, "node_modules", "fixture-unscoped")); err == nil {
		pkgInstalled = true
	} else if _, err := os.Stat(filepath.Join(dir, "node_modules", "fixture-unscoped")); err == nil {
		pkgInstalled = true
	}
	if !pkgInstalled {
		t.Errorf("fixture-unscoped was not installed in workspace")
	}
}

func TestPnpm_OfflineAndCache(t *testing.T) {
	skipIfPnpmMissing(t)
	h := NewTestHarness(t)

	pkgJSON := `{
  "name": "test-pnpm-offline",
  "version": "1.0.0",
  "dependencies": {
    "fixture-unscoped": "1.0.0"
  }
}
`
	workDir := setupPnpmWorkspace(t, h.GatewayURL(), pkgJSON)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Initial install
	stdout, stderr, code, err := runPnpm(ctx, workDir, h.GatewayURL(), "install")
	if err != nil || code != 0 {
		t.Fatalf("initial pnpm install failed: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}

	// Remove node_modules
	_ = os.RemoveAll(filepath.Join(workDir, "node_modules"))

	// Offline install from store
	stdout, stderr, code, err = runPnpm(ctx, workDir, h.GatewayURL(), "install", "--offline")
	if err != nil || code != 0 {
		t.Fatalf("pnpm install --offline failed: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}

	AssertInstalledPackage(t, workDir, "fixture-unscoped", "1.0.0")
}

func TestPnpm_CorruptedTarballRejected(t *testing.T) {
	skipIfPnpmMissing(t)
	h := NewTestHarness(t)

	pkgJSON := `{
  "name": "test-pnpm-corrupted",
  "version": "1.0.0",
  "dependencies": {
    "fixture-tampered": "1.0.0"
  }
}
`
	workDir := setupPnpmWorkspace(t, h.GatewayURL(), pkgJSON)

	// Corrupt upstream tarball
	h.SetCorrupted("fixture-tampered", true)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	stdout, stderr, code, err := runPnpm(ctx, workDir, h.GatewayURL(), "install")
	if err == nil && code == 0 {
		t.Fatal("CRITICAL: pnpm install SUCCEEDED on corrupted tarball! Client failed integrity verification!")
	}

	combinedOutput := stdout + "\n" + stderr
	t.Logf("Verbatim client rejection of corrupted tarball:\n%s", combinedOutput)

	// Restore and confirm recovery
	h.SetCorrupted("fixture-tampered", false)
	_ = os.RemoveAll(filepath.Join(workDir, "node_modules"))

	stdout2, stderr2, code2, err2 := runPnpm(ctx, workDir, h.GatewayURL(), "install")
	if err2 != nil || code2 != 0 {
		t.Fatalf("restored pnpm install failed: %v\nstdout: %s\nstderr: %s", err2, stdout2, stderr2)
	}

	AssertInstalledPackage(t, workDir, "fixture-tampered", "1.0.0")
}
