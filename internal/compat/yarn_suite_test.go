package compat

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func skipIfYarnMissing(t *testing.T) {
	t.Helper()
	requirePackageManager(t, "yarn")
}

func setupYarnWorkspace(t *testing.T, gatewayURL string, pkgJSONContent string) string {
	t.Helper()
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkgJSONContent), 0o644); err != nil {
		t.Fatalf("failed writing package.json: %v", err)
	}

	// Yarn classic uses .yarnrc and .npmrc
	yarnrcContent := fmt.Sprintf("registry %q\n", gatewayURL)
	if err := os.WriteFile(filepath.Join(dir, ".yarnrc"), []byte(yarnrcContent), 0o644); err != nil {
		t.Fatalf("failed writing .yarnrc: %v", err)
	}
	npmrcContent := fmt.Sprintf("registry=%s/\n", gatewayURL)
	if err := os.WriteFile(filepath.Join(dir, ".npmrc"), []byte(npmrcContent), 0o644); err != nil {
		t.Fatalf("failed writing .npmrc: %v", err)
	}

	return dir
}

func runYarn(ctx context.Context, dir, gatewayURL string, args ...string) (string, string, int, error) {
	env := IsolatedClientEnv(dir, gatewayURL)
	finalArgs := append([]string{"--registry", gatewayURL + "/"}, args...)
	return RunCmd(ctx, dir, env, "yarn", finalArgs...)
}

func TestYarn_ScopedAndUnscopedInstall(t *testing.T) {
	skipIfYarnMissing(t)
	h := NewTestHarness(t)

	pkgJSON := `{
  "name": "test-yarn-scoped-unscoped",
  "version": "1.0.0",
  "dependencies": {
    "fixture-unscoped": "1.0.0",
    "@testscope/fixture-scoped": "1.0.0"
  }
}
`
	workDir := setupYarnWorkspace(t, h.GatewayURL(), pkgJSON)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	stdout, stderr, code, err := runYarn(ctx, workDir, h.GatewayURL(), "install")
	if err != nil || code != 0 {
		t.Fatalf("yarn install failed (code %d): err=%v\nstdout: %s\nstderr: %s", code, err, stdout, stderr)
	}

	AssertInstalledPackage(t, workDir, "fixture-unscoped", "1.0.0")
	AssertInstalledPackage(t, workDir, "@testscope/fixture-scoped", "1.0.0")

	// Verify yarn.lock contains integrity hashes
	lockData, err := os.ReadFile(filepath.Join(workDir, "yarn.lock"))
	if err != nil {
		t.Fatalf("failed reading yarn.lock: %v", err)
	}
	lockStr := string(lockData)
	if !strings.Contains(lockStr, "fixture-unscoped") {
		t.Errorf("yarn.lock does not contain fixture-unscoped")
	}
}

func TestYarn_PeerAndOptionalDependencies(t *testing.T) {
	skipIfYarnMissing(t)
	h := NewTestHarness(t)

	pkgJSON := `{
  "name": "test-yarn-peer-optional",
  "version": "1.0.0",
  "dependencies": {
    "fixture-peer": "1.0.0",
    "fixture-optional": "1.0.0"
  }
}
`
	workDir := setupYarnWorkspace(t, h.GatewayURL(), pkgJSON)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	stdout, stderr, code, err := runYarn(ctx, workDir, h.GatewayURL(), "install")
	if err != nil || code != 0 {
		t.Fatalf("yarn install failed (code %d): err=%v\nstdout: %s\nstderr: %s", code, err, stdout, stderr)
	}

	AssertInstalledPackage(t, workDir, "fixture-peer", "1.0.0")
	AssertInstalledPackage(t, workDir, "fixture-optional", "1.0.0")
	AssertInstalledPackage(t, workDir, "fixture-unscoped", "1.0.0")
}

func TestYarn_LockfileDrivenInstall(t *testing.T) {
	skipIfYarnMissing(t)
	h := NewTestHarness(t)

	pkgJSON := `{
  "name": "test-yarn-lockfile",
  "version": "1.0.0",
  "dependencies": {
    "fixture-unscoped": "1.0.0"
  }
}
`
	workDir := setupYarnWorkspace(t, h.GatewayURL(), pkgJSON)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Initial install to generate yarn.lock
	stdout, stderr, code, err := runYarn(ctx, workDir, h.GatewayURL(), "install")
	if err != nil || code != 0 {
		t.Fatalf("initial yarn install failed: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}

	// Remove node_modules
	_ = os.RemoveAll(filepath.Join(workDir, "node_modules"))

	// Frozen lockfile install
	stdout, stderr, code, err = runYarn(ctx, workDir, h.GatewayURL(), "install", "--frozen-lockfile")
	if err != nil || code != 0 {
		t.Fatalf("yarn install --frozen-lockfile failed: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}

	AssertInstalledPackage(t, workDir, "fixture-unscoped", "1.0.0")
}

func TestYarn_Workspaces(t *testing.T) {
	skipIfYarnMissing(t)
	h := NewTestHarness(t)

	dir := t.TempDir()
	rootPkgJSON := `{
  "name": "test-yarn-workspaces-root",
  "private": true,
  "workspaces": [
    "packages/*"
  ]
}
`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(rootPkgJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	yarnrcContent := fmt.Sprintf("registry %q\n", h.GatewayURL())
	if err := os.WriteFile(filepath.Join(dir, ".yarnrc"), []byte(yarnrcContent), 0o644); err != nil {
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

	stdout, stderr, code, err := runYarn(ctx, dir, h.GatewayURL(), "install")
	if err != nil || code != 0 {
		t.Fatalf("yarn install in workspace failed: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}

	AssertInstalledPackage(t, dir, "fixture-unscoped", "1.0.0")
}

func TestYarn_OfflineAndCache(t *testing.T) {
	skipIfYarnMissing(t)
	h := NewTestHarness(t)

	pkgJSON := `{
  "name": "test-yarn-offline",
  "version": "1.0.0",
  "dependencies": {
    "fixture-unscoped": "1.0.0"
  }
}
`
	workDir := setupYarnWorkspace(t, h.GatewayURL(), pkgJSON)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Initial install
	stdout, stderr, code, err := runYarn(ctx, workDir, h.GatewayURL(), "install")
	if err != nil || code != 0 {
		t.Fatalf("initial yarn install failed: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}

	// Remove node_modules
	_ = os.RemoveAll(filepath.Join(workDir, "node_modules"))

	// Offline install
	stdout, stderr, code, err = runYarn(ctx, workDir, h.GatewayURL(), "install", "--offline")
	if err != nil || code != 0 {
		t.Fatalf("yarn install --offline failed: %v\nstdout: %s\nstderr: %s", err, stdout, stderr)
	}

	AssertInstalledPackage(t, workDir, "fixture-unscoped", "1.0.0")
}

func TestYarn_CorruptedTarballRejected(t *testing.T) {
	skipIfYarnMissing(t)
	h := NewTestHarness(t)

	pkgJSON := `{
  "name": "test-yarn-corrupted",
  "version": "1.0.0",
  "dependencies": {
    "fixture-tampered": "1.0.0"
  }
}
`
	workDir := setupYarnWorkspace(t, h.GatewayURL(), pkgJSON)

	// Corrupt upstream tarball
	h.SetCorrupted("fixture-tampered", true)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	stdout, stderr, code, err := runYarn(ctx, workDir, h.GatewayURL(), "install")
	if err == nil && code == 0 {
		t.Fatal("CRITICAL: yarn install SUCCEEDED on corrupted tarball! Client failed integrity verification!")
	}

	combinedOutput := stdout + "\n" + stderr
	t.Logf("Verbatim client rejection of corrupted tarball:\n%s", combinedOutput)

	// Restore and confirm recovery
	h.SetCorrupted("fixture-tampered", false)
	_ = os.RemoveAll(filepath.Join(workDir, "node_modules"))

	stdout2, stderr2, code2, err2 := runYarn(ctx, workDir, h.GatewayURL(), "install")
	if err2 != nil || code2 != 0 {
		t.Fatalf("restored yarn install failed: %v\nstdout: %s\nstderr: %s", err2, stdout2, stderr2)
	}

	AssertInstalledPackage(t, workDir, "fixture-tampered", "1.0.0")
}
