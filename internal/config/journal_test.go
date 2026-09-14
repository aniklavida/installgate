package config

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestJournal_InterruptedEnableRecovery(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewFileStateStore(tempDir)
	if err != nil {
		t.Fatal(err)
	}

	npmrcPath := filepath.Join(tempDir, ".npmrc")
	originalContent := []byte("registry=https://registry.npmjs.org/\n")
	if err := os.WriteFile(npmrcPath, originalContent, 0o644); err != nil {
		t.Fatal(err)
	}

	prior := PriorConfig{
		FileExisted:   true,
		HasRegistry:   true,
		RegistryValue: "https://registry.npmjs.org/",
		RawContent:    originalContent,
	}

	// 1. Begin transaction
	tx, err := BeginTransaction(store, ActionEnable, npmrcPath, "http://127.0.0.1:8765", prior)
	if err != nil {
		t.Fatal(err)
	}

	// 2. Stage new content to temp file
	stagedPath, err := StageTransaction(store, tx, []byte("registry=http://127.0.0.1:8765/\n"))
	if err != nil {
		t.Fatal(err)
	}

	// Verify staged file exists
	if _, err := os.Stat(stagedPath); err != nil {
		t.Fatalf("expected staged file to exist: %v", err)
	}

	// 3. Simulate crash before commit: RecoverJournal is invoked on next run
	res, err := RecoverJournal(store)
	if err != nil {
		t.Fatalf("RecoverJournal failed: %v", err)
	}
	if res == nil {
		t.Fatal("expected recovery result, got nil")
	}
	if res.Status != "rolled_back" {
		t.Errorf("got status %q, want rolled_back", res.Status)
	}

	// Staged file must be cleaned up
	if _, err := os.Stat(stagedPath); !os.IsNotExist(err) {
		t.Errorf("staged temp file was not deleted after recovery")
	}

	// Journal must be cleared
	active, err := store.ReadJournal()
	if err != nil {
		t.Fatal(err)
	}
	if active != nil {
		t.Errorf("journal was not cleared after recovery: %+v", active)
	}

	// Target .npmrc must be restored to original bytes
	currentContent, err := os.ReadFile(npmrcPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(currentContent, originalContent) {
		t.Errorf("target file content was not restored byte-for-byte:\ngot:\n%s\nwant:\n%s", string(currentContent), string(originalContent))
	}
}

func TestJournal_InterruptedDisableRecovery(t *testing.T) {
	tempDir := t.TempDir()
	store, err := NewFileStateStore(tempDir)
	if err != nil {
		t.Fatal(err)
	}

	npmrcPath := filepath.Join(tempDir, ".npmrc")
	originalContent := []byte("save-exact=true\n")
	// Currently pointing at gateway
	if err := os.WriteFile(npmrcPath, []byte("registry=http://127.0.0.1:8765/\nsave-exact=true\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	prior := PriorConfig{
		FileExisted: true,
		HasRegistry: false,
		RawContent:  originalContent,
	}

	// 1. Begin disable transaction
	tx, err := BeginTransaction(store, ActionDisable, npmrcPath, "http://127.0.0.1:8765", prior)
	if err != nil {
		t.Fatal(err)
	}

	// 2. Stage restoration content
	stagedPath, err := StageTransaction(store, tx, originalContent)
	if err != nil {
		t.Fatal(err)
	}

	// 3. Simulate crash before commit: RecoverJournal is invoked on next run
	res, err := RecoverJournal(store)
	if err != nil {
		t.Fatalf("RecoverJournal failed: %v", err)
	}
	if res == nil {
		t.Fatal("expected recovery result, got nil")
	}
	if res.Status != "completed" {
		t.Errorf("got status %q, want completed", res.Status)
	}

	// Staged file must be cleaned up
	if _, err := os.Stat(stagedPath); !os.IsNotExist(err) {
		t.Errorf("staged temp file was not deleted after recovery")
	}

	// Target .npmrc must be completed and restored to original bytes
	currentContent, err := os.ReadFile(npmrcPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(currentContent, originalContent) {
		t.Errorf("target file was not restored byte-for-byte:\ngot:\n%s\nwant:\n%s", string(currentContent), string(originalContent))
	}
}

// Subprocess crash target used by TestJournal_ActualProcessInterruptionRecovery
func init() {
	if os.Getenv("TEST_CRASH_SUBPROCESS") == "1" {
		dataDir := os.Getenv("TEST_DATA_DIR")
		npmrcPath := os.Getenv("TEST_NPMRC_PATH")

		mgr, err := NewLifecycleManager(
			WithDataDir(dataDir),
			WithNpmrcPath(npmrcPath),
			WithGatewayURL("http://127.0.0.1:8765"),
			WithHealthChecker(func(ctx context.Context, gatewayURL string) (*HealthResponse, error) {
				return &HealthResponse{Status: "ok", Ready: true}, nil
			}),
			WithPreCommitHook(func() {
				// Kill the process violently mid-write with SIGKILL
				p, _ := os.FindProcess(os.Getpid())
				_ = p.Signal(syscall.SIGKILL)
			}),
		)
		if err != nil {
			os.Exit(2)
		}

		_ = mgr.EnableNpm(context.Background())
		os.Exit(0)
	}
}

func TestJournal_ActualProcessInterruptionRecovery(t *testing.T) {
	tempDir := t.TempDir()
	dataDir := filepath.Join(tempDir, "data")
	npmrcPath := filepath.Join(tempDir, ".npmrc")

	originalContent := []byte("# Developer config\nsave-exact=true\n")
	if err := os.WriteFile(npmrcPath, originalContent, 0o644); err != nil {
		t.Fatal(err)
	}

	// 1. Launch child process that commits suicide violently mid-write
	cmd := exec.Command(os.Args[0], "-test.run=TestJournal_ActualProcessInterruptionRecovery")
	cmd.Env = append(os.Environ(),
		"TEST_CRASH_SUBPROCESS=1",
		"TEST_DATA_DIR="+dataDir,
		"TEST_NPMRC_PATH="+npmrcPath,
	)

	err := cmd.Run()
	// The process MUST have exited with failure due to SIGKILL
	if err == nil {
		t.Fatal("expected subprocess to be killed, but exited cleanly")
	}

	// 2. Next run: initialize LifecycleManager and run status / recovery
	mgr, err := NewLifecycleManager(
		WithDataDir(dataDir),
		WithNpmrcPath(npmrcPath),
		WithGatewayURL("http://127.0.0.1:8765"),
		WithHealthChecker(func(ctx context.Context, gatewayURL string) (*HealthResponse, error) {
			return &HealthResponse{Status: "ok", Ready: true}, nil
		}),
	)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	rep, err := mgr.Status(context.Background())
	if err != nil {
		t.Fatalf("Status failed: %v", err)
	}

	if rep.RecoveryNote == "" {
		t.Fatalf("expected RecoveryNote indicating interrupted transaction was recovered")
	}

	// Verify .npmrc was restored byte-for-byte to original state
	finalContent, err := os.ReadFile(npmrcPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(finalContent, originalContent) {
		t.Fatalf("content after recovery mismatch:\ngot:\n%s\nwant:\n%s", string(finalContent), string(originalContent))
	}

	// 3. Verify that a subsequent normal enable succeeds completely now that journal is clean
	if err := mgr.EnableNpm(context.Background()); err != nil {
		t.Fatalf("subsequent enable failed: %v", err)
	}

	enabledContent, err := os.ReadFile(npmrcPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(enabledContent), "registry=http://127.0.0.1:8765/") {
		t.Fatalf("expected enabled registry line: %s", string(enabledContent))
	}

	// 4. Verify disable cleans it back to original bytes
	if err := mgr.DisableNpm(context.Background()); err != nil {
		t.Fatalf("disable failed: %v", err)
	}

	finalRestored, err := os.ReadFile(npmrcPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(finalRestored, originalContent) {
		t.Fatalf("final restored mismatch:\ngot:\n%s\nwant:\n%s", string(finalRestored), string(originalContent))
	}
}
