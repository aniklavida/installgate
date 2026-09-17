package compat

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aniklavida/installgate/internal/config"
)

func skipIfNpmMissing(t *testing.T) {
	t.Helper()
	requirePackageManager(t, "npm")
}

func setupNpmWorkspace(t *testing.T, gatewayURL string, pkgJSONContent string) string {
	t.Helper()
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkgJSONContent), 0o644); err != nil {
		t.Fatalf("failed writing package.json: %v", err)
	}

	npmrcContent := fmt.Sprintf("registry=%s/\naudit=false\nfund=false\n", gatewayURL)
	if err := os.WriteFile(filepath.Join(dir, ".npmrc"), []byte(npmrcContent), 0o644); err != nil {
		t.Fatalf("failed writing .npmrc: %v", err)
	}

	return dir
}

func runNpm(ctx context.Context, dir, gatewayURL string, args ...string) (string, string, int, error) {
	env := IsolatedClientEnv(dir, gatewayURL)
	return RunCmd(ctx, dir, env, "npm", args...)
}

func TestNpm_ScopedAndUnscopedInstall(t *testing.T) {
	skipIfNpmMissing(t)
	h := NewTestHarness(t)

	pkgJSON := `{
  "name": "test-npm-scoped-unscoped",
  "version": "1.0.0",
  "dependencies": {
    "fixture-unscoped": "1.0.0",
    "@testscope/fixture-scoped": "1.0.0"
  }
}
`
	workDir := setupNpmWorkspace(t, h.GatewayURL(), pkgJSON)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	stdout, stderr, code, err := runNpm(ctx, workDir, h.GatewayURL(), "install")
	if err != nil || code != 0 {
		t.Fatalf("npm install failed (code %d): err=%v\nstdout: %s\nstderr: %s", code, err, stdout, stderr)
	}

	AssertInstalledPackage(t, workDir, "fixture-unscoped", "1.0.0")
	AssertInstalledPackage(t, workDir, "@testscope/fixture-scoped", "1.0.0")

	// Verify package-lock.json contains sha512 integrity hashes
	lockData, err := os.ReadFile(filepath.Join(workDir, "package-lock.json"))
	if err != nil {
		t.Fatalf("failed reading package-lock.json: %v", err)
	}
	lockStr := string(lockData)
	if !strings.Contains(lockStr, h.Packages["fixture-unscoped"].IntegritySHA512) {
		t.Errorf("package-lock.json does not contain fixture-unscoped sha512 integrity hash")
	}
	if !strings.Contains(lockStr, h.Packages["@testscope/fixture-scoped"].IntegritySHA512) {
		t.Errorf("package-lock.json does not contain @testscope/fixture-scoped sha512 integrity hash")
	}
}

func TestNpm_PeerAndOptionalDependencies(t *testing.T) {
	skipIfNpmMissing(t)
	h := NewTestHarness(t)

	pkgJSON := `{
  "name": "test-npm-peer-optional",
  "version": "1.0.0",
  "dependencies": {
    "fixture-peer": "1.0.0",
    "fixture-optional": "1.0.0"
  }
}
`
	workDir := setupNpmWorkspace(t, h.GatewayURL(), pkgJSON)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	stdout, stderr, code, err := runNpm(ctx, workDir, h.GatewayURL(), "install")
	if err != nil || code != 0 {
		t.Fatalf("npm install failed (code %d): err=%v\nstdout: %s\nstderr: %s", code, err, stdout, stderr)
	}

	AssertInstalledPackage(t, workDir, "fixture-peer", "1.0.0")
	AssertInstalledPackage(t, workDir, "fixture-optional", "1.0.0")
	AssertInstalledPackage(t, workDir, "fixture-unscoped", "1.0.0")
}

func TestNpm_LockfileDrivenInstall(t *testing.T) {
	skipIfNpmMissing(t)
	h := NewTestHarness(t)

	pkgJSON := `{
  "name": "test-npm-lockfile",
  "version": "1.0.0",
  "dependencies": {
    "fixture-unscoped": "1.0.0"
  }
}
`
	workDir := setupNpmWorkspace(t, h.GatewayURL(), pkgJSON)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// 1. Initial install to produce lockfile
	stdout, stderr, code, err := runNpm(ctx, workDir, h.GatewayURL(), "install")
	if err != nil || code != 0 {
		t.Fatalf("initial npm install failed: %v\n%s\n%s", err, stdout, stderr)
	}

	// 2. Remove node_modules
	if err := os.RemoveAll(filepath.Join(workDir, "node_modules")); err != nil {
		t.Fatalf("failed removing node_modules: %v", err)
	}

	// 3. Clean install strictly from lockfile (npm ci)
	stdout, stderr, code, err = runNpm(ctx, workDir, h.GatewayURL(), "ci")
	if err != nil || code != 0 {
		t.Fatalf("npm ci failed: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}

	AssertInstalledPackage(t, workDir, "fixture-unscoped", "1.0.0")
}

func TestNpm_Workspaces(t *testing.T) {
	skipIfNpmMissing(t)
	h := NewTestHarness(t)

	dir := t.TempDir()
	rootPkgJSON := `{
  "name": "test-npm-workspaces-root",
  "private": true,
  "workspaces": [
    "packages/*"
  ]
}
`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(rootPkgJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	npmrcContent := fmt.Sprintf("registry=%s/\naudit=false\nfund=false\n", h.GatewayURL())
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

	stdout, stderr, code, err := runNpm(ctx, dir, h.GatewayURL(), "install")
	if err != nil || code != 0 {
		t.Fatalf("npm install in workspaces failed (code %d): %v\nstdout: %s\nstderr: %s", code, err, stdout, stderr)
	}

	AssertInstalledPackage(t, dir, "fixture-unscoped", "1.0.0")
}

func TestNpm_OfflineAndCache(t *testing.T) {
	skipIfNpmMissing(t)
	h := NewTestHarness(t)

	pkgJSON := `{
  "name": "test-npm-offline",
  "version": "1.0.0",
  "dependencies": {
    "fixture-unscoped": "1.0.0"
  }
}
`
	workDir := setupNpmWorkspace(t, h.GatewayURL(), pkgJSON)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Initial install to populate cache
	stdout, stderr, code, err := runNpm(ctx, workDir, h.GatewayURL(), "install")
	if err != nil || code != 0 {
		t.Fatalf("initial npm install failed: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}

	// Remove node_modules
	_ = os.RemoveAll(filepath.Join(workDir, "node_modules"))

	// Offline install from local cache
	stdout, stderr, code, err = runNpm(ctx, workDir, h.GatewayURL(), "install", "--prefer-offline")
	if err != nil || code != 0 {
		t.Fatalf("npm install --prefer-offline failed: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}

	AssertInstalledPackage(t, workDir, "fixture-unscoped", "1.0.0")
}

func TestNpm_CorruptedTarballRejected(t *testing.T) {
	skipIfNpmMissing(t)
	h := NewTestHarness(t)

	pkgJSON := `{
  "name": "test-npm-corrupted",
  "version": "1.0.0",
  "dependencies": {
    "fixture-tampered": "1.0.0"
  }
}
`
	workDir := setupNpmWorkspace(t, h.GatewayURL(), pkgJSON)

	// 1. Tamper: corrupt upstream tarball
	h.SetCorrupted("fixture-tampered", true)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	stdout, stderr, code, err := runNpm(ctx, workDir, h.GatewayURL(), "install")
	if err == nil && code == 0 {
		t.Fatal("CRITICAL: npm install SUCCEEDED on corrupted tarball! Client failed integrity verification!")
	}

	combinedOutput := stdout + "\n" + stderr
	t.Logf("Verbatim client rejection of corrupted tarball:\n%s", combinedOutput)

	// Confirm npm failed with integrity error or gateway blocked with 403
	if !strings.Contains(combinedOutput, "EINTEGRITY") &&
		!strings.Contains(combinedOutput, "integrity checksum") &&
		!strings.Contains(combinedOutput, "403 Forbidden") &&
		!strings.Contains(combinedOutput, "InstallGate") {
		t.Errorf("expected rejection output to indicate integrity or 403 failure; got: %s", combinedOutput)
	}

	// 2. Restore tarball and confirm recovery
	h.SetCorrupted("fixture-tampered", false)
	_ = os.RemoveAll(filepath.Join(workDir, "node_modules"))

	stdout2, stderr2, code2, err2 := runNpm(ctx, workDir, h.GatewayURL(), "install")
	if err2 != nil || code2 != 0 {
		t.Fatalf("restored npm install failed: %v\nstdout: %s\nstderr: %s", err2, stdout2, stderr2)
	}

	AssertInstalledPackage(t, workDir, "fixture-tampered", "1.0.0")
}

func TestNpm_EnableDisableLifecycle(t *testing.T) {
	skipIfNpmMissing(t)
	h := NewTestHarness(t)

	tempDir := t.TempDir()
	dataDir := filepath.Join(tempDir, "data")
	npmrcPath := filepath.Join(tempDir, ".npmrc")

	originalContent := []byte("registry=https://registry.npmjs.org/\naudit=false\n")
	if err := os.WriteFile(npmrcPath, originalContent, 0o644); err != nil {
		t.Fatal(err)
	}

	mgr, err := config.NewLifecycleManager(
		config.WithDataDir(dataDir),
		config.WithNpmrcPath(npmrcPath),
		config.WithGatewayURL(h.GatewayURL()),
		config.WithHealthChecker(func(ctx context.Context, gatewayURL string) (*config.HealthResponse, error) {
			return &config.HealthResponse{Status: "ok", Ready: true}, nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	// 1. Enable
	if err := mgr.EnableNpm(ctx); err != nil {
		t.Fatalf("EnableNpm failed: %v", err)
	}

	// Verify .npmrc points to gateway
	info, err := config.InspectNpmrc(npmrcPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(info.RegistryValue, h.GatewayURL()) {
		t.Fatalf("expected registry to point to gateway %s, got %s", h.GatewayURL(), info.RegistryValue)
	}

	// 2. Disable
	if err := mgr.DisableNpm(ctx); err != nil {
		t.Fatalf("DisableNpm failed: %v", err)
	}

	// Verify byte-for-byte restoration
	restored, err := os.ReadFile(npmrcPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != string(originalContent) {
		t.Fatalf("restored content is not byte-identical to original:\ngot  %q\nwant %q", string(restored), string(originalContent))
	}
}
