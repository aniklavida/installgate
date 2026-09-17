package compat

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func skipIfBunMissing(t *testing.T) {
	t.Helper()
	requirePackageManager(t, "bun")
	if runtime.GOOS == "windows" {
		t.Log("Note: Bun Windows support under proxying registries has known upstream limitations.")
	}
}

func setupBunWorkspace(t *testing.T, gatewayURL string, pkgJSONContent string) string {
	t.Helper()
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkgJSONContent), 0o644); err != nil {
		t.Fatalf("failed writing package.json: %v", err)
	}

	// Bun supports bunfig.toml and .npmrc
	bunfigContent := fmt.Sprintf("[install]\nregistry = %q\n", gatewayURL)
	if err := os.WriteFile(filepath.Join(dir, "bunfig.toml"), []byte(bunfigContent), 0o644); err != nil {
		t.Fatalf("failed writing bunfig.toml: %v", err)
	}

	npmrcContent := fmt.Sprintf("registry=%s/\n", gatewayURL)
	if err := os.WriteFile(filepath.Join(dir, ".npmrc"), []byte(npmrcContent), 0o644); err != nil {
		t.Fatalf("failed writing .npmrc: %v", err)
	}

	return dir
}

func runBun(ctx context.Context, dir, gatewayURL string, args ...string) (string, string, int, error) {
	env := IsolatedClientEnv(dir, gatewayURL)
	finalArgs := append([]string{"install", "--registry", gatewayURL + "/"}, args...)
	return RunCmd(ctx, dir, env, "bun", finalArgs...)
}

func TestBun_ScopedAndUnscopedInstall(t *testing.T) {
	skipIfBunMissing(t)
	h := NewTestHarness(t)

	pkgJSON := `{
  "name": "test-bun-scoped-unscoped",
  "version": "1.0.0",
  "dependencies": {
    "fixture-unscoped": "1.0.0",
    "@testscope/fixture-scoped": "1.0.0"
  }
}
`
	workDir := setupBunWorkspace(t, h.GatewayURL(), pkgJSON)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	stdout, stderr, code, err := runBun(ctx, workDir, h.GatewayURL())
	if err != nil || code != 0 {
		t.Fatalf("bun install failed (code %d): err=%v\nstdout: %s\nstderr: %s", code, err, stdout, stderr)
	}

	AssertInstalledPackage(t, workDir, "fixture-unscoped", "1.0.0")
	AssertInstalledPackage(t, workDir, "@testscope/fixture-scoped", "1.0.0")
}

func TestBun_PeerAndOptionalDependencies(t *testing.T) {
	skipIfBunMissing(t)
	h := NewTestHarness(t)

	pkgJSON := `{
  "name": "test-bun-peer-optional",
  "version": "1.0.0",
  "dependencies": {
    "fixture-peer": "1.0.0",
    "fixture-optional": "1.0.0"
  }
}
`
	workDir := setupBunWorkspace(t, h.GatewayURL(), pkgJSON)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	stdout, stderr, code, err := runBun(ctx, workDir, h.GatewayURL())
	if err != nil || code != 0 {
		t.Fatalf("bun install failed (code %d): err=%v\nstdout: %s\nstderr: %s", code, err, stdout, stderr)
	}

	AssertInstalledPackage(t, workDir, "fixture-peer", "1.0.0")
	AssertInstalledPackage(t, workDir, "fixture-optional", "1.0.0")
	AssertInstalledPackage(t, workDir, "fixture-unscoped", "1.0.0")
}

func TestBun_LockfileDrivenInstall(t *testing.T) {
	skipIfBunMissing(t)
	h := NewTestHarness(t)

	pkgJSON := `{
  "name": "test-bun-lockfile",
  "version": "1.0.0",
  "dependencies": {
    "fixture-unscoped": "1.0.0"
  }
}
`
	workDir := setupBunWorkspace(t, h.GatewayURL(), pkgJSON)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Initial install
	stdout, stderr, code, err := runBun(ctx, workDir, h.GatewayURL())
	if err != nil || code != 0 {
		t.Fatalf("initial bun install failed: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}

	// Remove node_modules
	_ = os.RemoveAll(filepath.Join(workDir, "node_modules"))

	// Frozen lockfile install
	stdout, stderr, code, err = runBun(ctx, workDir, h.GatewayURL(), "--frozen-lockfile")
	if err != nil || code != 0 {
		t.Fatalf("bun install --frozen-lockfile failed: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}

	AssertInstalledPackage(t, workDir, "fixture-unscoped", "1.0.0")
}

func TestBun_Workspaces(t *testing.T) {
	skipIfBunMissing(t)
	h := NewTestHarness(t)

	dir := t.TempDir()
	rootPkgJSON := `{
  "name": "test-bun-workspaces-root",
  "private": true,
  "workspaces": [
    "packages/*"
  ]
}
`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(rootPkgJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	bunfigContent := fmt.Sprintf("[install]\nregistry = %q\n", h.GatewayURL())
	if err := os.WriteFile(filepath.Join(dir, "bunfig.toml"), []byte(bunfigContent), 0o644); err != nil {
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

	stdout, stderr, code, err := runBun(ctx, dir, h.GatewayURL())
	if err != nil || code != 0 {
		t.Fatalf("bun install in workspace failed: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}

	AssertInstalledPackage(t, dir, "fixture-unscoped", "1.0.0")
}

func TestBun_OfflineAndCache(t *testing.T) {
	skipIfBunMissing(t)
	h := NewTestHarness(t)

	pkgJSON := `{
  "name": "test-bun-offline",
  "version": "1.0.0",
  "dependencies": {
    "fixture-unscoped": "1.0.0"
  }
}
`
	workDir := setupBunWorkspace(t, h.GatewayURL(), pkgJSON)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Initial install
	stdout, stderr, code, err := runBun(ctx, workDir, h.GatewayURL())
	if err != nil || code != 0 {
		t.Fatalf("initial bun install failed: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}

	// Remove node_modules
	_ = os.RemoveAll(filepath.Join(workDir, "node_modules"))

	// Offline install
	stdout, stderr, code, err = runBun(ctx, workDir, h.GatewayURL(), "--offline")
	if err != nil || code != 0 {
		t.Fatalf("bun install --offline failed: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}

	AssertInstalledPackage(t, workDir, "fixture-unscoped", "1.0.0")
}

func TestBun_CorruptedTarballRejected(t *testing.T) {
	skipIfBunMissing(t)
	h := NewTestHarness(t)

	pkgJSON := `{
  "name": "test-bun-corrupted",
  "version": "1.0.0",
  "dependencies": {
    "fixture-tampered": "1.0.0"
  }
}
`
	workDir := setupBunWorkspace(t, h.GatewayURL(), pkgJSON)

	// Corrupt upstream tarball
	h.SetCorrupted("fixture-tampered", true)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	stdout, stderr, code, err := runBun(ctx, workDir, h.GatewayURL())
	if err == nil && code == 0 {
		t.Fatal("CRITICAL: bun install SUCCEEDED on corrupted tarball! Client failed integrity verification!")
	}

	combinedOutput := stdout + "\n" + stderr
	t.Logf("Verbatim client rejection of corrupted tarball:\n%s", combinedOutput)

	// Restore and confirm recovery
	h.SetCorrupted("fixture-tampered", false)
	_ = os.RemoveAll(filepath.Join(workDir, "node_modules"))

	stdout2, stderr2, code2, err2 := runBun(ctx, workDir, h.GatewayURL())
	if err2 != nil || code2 != 0 {
		t.Fatalf("restored bun install failed: %v\nstdout: %s\nstderr: %s", err2, stdout2, stderr2)
	}

	AssertInstalledPackage(t, workDir, "fixture-tampered", "1.0.0")
}
