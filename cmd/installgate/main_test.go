package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aniklavida/installgate/internal/evidence"
	"github.com/aniklavida/installgate/internal/explanation"
	"github.com/aniklavida/installgate/internal/verdict"
)

func buildBinary(t *testing.T) string {
	t.Helper()
	tempDir := t.TempDir()
	binPath := filepath.Join(tempDir, "installgate")

	cmd := exec.Command("go", "build", "-o", binPath, ".")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build binary: %v\noutput: %s", err, string(out))
	}

	return binPath
}

func TestCLI_Version(t *testing.T) {
	bin := buildBinary(t)

	cmd := exec.Command(bin, "version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("version failed: %v", err)
	}

	if !strings.Contains(string(out), "installgate dev") {
		t.Errorf("unexpected version output: %s", string(out))
	}
}

func TestCLI_Doctor(t *testing.T) {
	bin := buildBinary(t)

	cmd := exec.Command(bin, "doctor")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("doctor failed: %v", err)
	}

	expected := "InstallGate foundation: OK"
	if !strings.Contains(string(out), expected) {
		t.Errorf("unexpected doctor output: %s", string(out))
	}
	if !strings.Contains(string(out), "Registry gateway: planned for v1.0") {
		t.Errorf("doctor must preserve truthful support claim: %s", string(out))
	}
}

func TestCLI_Explain_HumanAndJSON(t *testing.T) {
	bin := buildBinary(t)
	dataDir := t.TempDir()

	store, err := explanation.NewFileStore(filepath.Join(dataDir, "decisions"))
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}

	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	snap := evidence.NewSnapshot("test-pkg", "1.0.0", []verdict.Signal{
		{
			Kind:        evidence.KindVulnerability,
			Source:      "osv",
			Observation: "critical",
			Confidence:  evidence.ConfidenceHigh,
			RetrievedAt: now,
			FreshUntil:  now.Add(1 * time.Hour),
		},
	}, nil, now)

	dec := verdict.Decision{
		Verdict: verdict.Block,
		Reasons: []verdict.Reason{
			{
				RuleID:      "core.vulnerability-threshold",
				Summary:     "vulnerability exceeds the configured threshold",
				SignalKinds: []string{evidence.KindVulnerability},
			},
		},
	}

	doc, err := explanation.NewDecisionDocument("test-pkg", "1.0.0", dec, snap, explanation.WithReferenceTime(now))
	if err != nil {
		t.Fatalf("NewDecisionDocument failed: %v", err)
	}

	if err := store.Save(doc); err != nil {
		t.Fatalf("failed to save doc in store: %v", err)
	}

	// 1. Human explain
	cmdHuman := exec.Command(bin, "explain", doc.DecisionID)
	cmdHuman.Env = append(os.Environ(), "INSTALLGATE_DATA_DIR="+dataDir)
	outHuman, err := cmdHuman.CombinedOutput()
	if err != nil {
		t.Fatalf("explain command failed: %v\noutput: %s", err, string(outHuman))
	}

	humanStr := string(outHuman)
	if !strings.Contains(humanStr, "InstallGate Decision: BLOCKED") {
		t.Errorf("human output missing verdict: %s", humanStr)
	}
	if !strings.Contains(humanStr, doc.DecisionID) {
		t.Errorf("human output missing decision ID: %s", humanStr)
	}
	if !strings.Contains(humanStr, "core.vulnerability-threshold") {
		t.Errorf("human output missing rule ID: %s", humanStr)
	}

	// 2. JSON explain
	cmdJSON := exec.Command(bin, "explain", "--json", doc.DecisionID)
	cmdJSON.Env = append(os.Environ(), "INSTALLGATE_DATA_DIR="+dataDir)
	outJSON, err := cmdJSON.CombinedOutput()
	if err != nil {
		t.Fatalf("explain --json failed: %v\noutput: %s", err, string(outJSON))
	}

	parsed, err := explanation.ParseJSON(outJSON)
	if err != nil {
		t.Fatalf("failed to parse JSON output: %v\noutput: %s", err, string(outJSON))
	}
	if parsed.DecisionID != doc.DecisionID {
		t.Errorf("parsed ID = %q, want %q", parsed.DecisionID, doc.DecisionID)
	}
	if parsed.Verdict != verdict.Block {
		t.Errorf("parsed Verdict = %q, want 'block'", parsed.Verdict)
	}
}

func TestCLI_Explain_NotFound(t *testing.T) {
	bin := buildBinary(t)
	dataDir := t.TempDir()

	cmd := exec.Command(bin, "explain", "dec_nonexistent")
	cmd.Env = append(os.Environ(), "INSTALLGATE_DATA_DIR="+dataDir)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected error explaining nonexistent ID, got nil")
	}

	if !strings.Contains(stderr.String(), "decision \"dec_nonexistent\" not found") {
		t.Errorf("unexpected stderr: %s", stderr.String())
	}
}

func TestCLI_Init(t *testing.T) {
	bin := buildBinary(t)
	dataDir := t.TempDir()

	cmd := exec.Command(bin, "init")
	cmd.Env = append(os.Environ(), "INSTALLGATE_DATA_DIR="+dataDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("init failed: %v\noutput: %s", err, string(out))
	}

	if !strings.Contains(string(out), "InstallGate initialized") {
		t.Errorf("unexpected init output: %s", string(out))
	}
}

func TestCLI_Status_Stopped(t *testing.T) {
	bin := buildBinary(t)
	dataDir := t.TempDir()
	npmrcPath := filepath.Join(t.TempDir(), ".npmrc")

	// 1. Human readable status
	cmd := exec.Command(bin, "status")
	cmd.Env = append(os.Environ(),
		"INSTALLGATE_DATA_DIR="+dataDir,
		"NPM_CONFIG_USERCONFIG="+npmrcPath,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("status failed: %v\noutput: %s", err, string(out))
	}

	outStr := string(out)
	if !strings.Contains(outStr, "Gateway process:  stopped") {
		t.Errorf("expected stopped gateway in output: %s", outStr)
	}
	if !strings.Contains(outStr, "Evidence cache:   unavailable (gateway not running)") {
		t.Errorf("expected cache unavailable in output: %s", outStr)
	}

	// 2. JSON status
	cmdJSON := exec.Command(bin, "status", "--json")
	cmdJSON.Env = append(os.Environ(),
		"INSTALLGATE_DATA_DIR="+dataDir,
		"NPM_CONFIG_USERCONFIG="+npmrcPath,
	)
	outJSON, err := cmdJSON.CombinedOutput()
	if err != nil {
		t.Fatalf("status --json failed: %v\noutput: %s", err, string(outJSON))
	}

	if !strings.Contains(string(outJSON), `"gateway_running": false`) {
		t.Errorf("expected gateway_running: false in JSON: %s", string(outJSON))
	}
}

func TestCLI_EnableNpm_RefuseWhenGatewayStopped(t *testing.T) {
	bin := buildBinary(t)
	dataDir := t.TempDir()
	npmrcPath := filepath.Join(t.TempDir(), ".npmrc")

	cmd := exec.Command(bin, "enable", "npm")
	cmd.Env = append(os.Environ(),
		"INSTALLGATE_DATA_DIR="+dataDir,
		"NPM_CONFIG_USERCONFIG="+npmrcPath,
		"INSTALLGATE_PORT=65432", // Unused port where nothing is running
	)

	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error enabling when gateway stopped, got success\noutput: %s", string(out))
	}

	if !strings.Contains(string(out), "gateway is not running or not ready") {
		t.Errorf("unexpected error message: %s", string(out))
	}
}

func TestCLI_EnableNpm_RefuseAuthTokensWithoutLeak(t *testing.T) {
	bin := buildBinary(t)
	dataDir := t.TempDir()
	npmrcPath := filepath.Join(t.TempDir(), ".npmrc")
	secret := "secret_npm_token_abcdef123456"
	content := "//registry.npmjs.org/:_authToken=" + secret + "\n"
	if err := os.WriteFile(npmrcPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(bin, "enable", "npm")
	cmd.Env = append(os.Environ(),
		"INSTALLGATE_DATA_DIR="+dataDir,
		"NPM_CONFIG_USERCONFIG="+npmrcPath,
	)

	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected failure when auth token is present, got nil")
	}

	outStr := string(out)
	// Invariant: NPM AUTH TOKENS ARE NEVER PERSISTED AND NEVER LOGGED
	if strings.Contains(outStr, secret) {
		t.Fatalf("SECURITY VIOLATION: secret auth token leaked to output: %s", outStr)
	}
}

func TestCLI_EnableNpm_RefusePrivateRegistry(t *testing.T) {
	bin := buildBinary(t)
	dataDir := t.TempDir()
	npmrcPath := filepath.Join(t.TempDir(), ".npmrc")
	content := "registry=https://npm.pkg.github.com/myorg\n"
	if err := os.WriteFile(npmrcPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(bin, "enable", "npm")
	cmd.Env = append(os.Environ(),
		"INSTALLGATE_DATA_DIR="+dataDir,
		"NPM_CONFIG_USERCONFIG="+npmrcPath,
	)

	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected failure on private registry, got nil")
	}

	if !strings.Contains(string(out), "private registry") {
		t.Errorf("expected private registry message, got: %s", string(out))
	}
}

func TestCLI_FullLifecycle(t *testing.T) {
	bin := buildBinary(t)
	dataDir := t.TempDir()
	npmrcPath := filepath.Join(t.TempDir(), ".npmrc")

	originalContent := []byte("# developer config\nsave-exact=true\n")
	if err := os.WriteFile(npmrcPath, originalContent, 0o644); err != nil {
		t.Fatal(err)
	}

	// Pick an ephemeral port
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	portStr := strconv.Itoa(port)

	// 1. Start gateway in foreground subprocess
	startCmd := exec.Command(bin, "start", "--foreground", "--port", portStr)
	startCmd.Env = append(os.Environ(),
		"INSTALLGATE_DATA_DIR="+dataDir,
		"NPM_CONFIG_USERCONFIG="+npmrcPath,
	)
	if err := startCmd.Start(); err != nil {
		t.Fatalf("failed to start gateway process: %v", err)
	}
	defer func() {
		if startCmd.Process != nil {
			_ = startCmd.Process.Kill()
		}
	}()

	// Wait for health endpoint
	healthURL := fmt.Sprintf("http://127.0.0.1:%d/-/installgate/health", port)
	client := &http.Client{Timeout: 1 * time.Second}
	ready := false
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		resp, err := client.Get(healthURL)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				ready = true
				break
			}
		}
	}
	if !ready {
		t.Fatal("gateway failed to become ready within 5s")
	}

	env := append(os.Environ(),
		"INSTALLGATE_DATA_DIR="+dataDir,
		"NPM_CONFIG_USERCONFIG="+npmrcPath,
		"INSTALLGATE_PORT="+portStr,
	)

	// 2. Run init
	initCmd := exec.Command(bin, "init")
	initCmd.Env = env
	if out, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("init failed: %v, out: %s", err, string(out))
	}

	// 3. Status before enable
	statusCmd := exec.Command(bin, "status")
	statusCmd.Env = env
	out, err := statusCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("status failed: %v, out: %s", err, string(out))
	}
	if !strings.Contains(string(out), "Gateway process:  running") {
		t.Errorf("status missing running: %s", string(out))
	}
	if !strings.Contains(string(out), "npm registry:     disabled") {
		t.Errorf("status should be disabled before enable: %s", string(out))
	}

	// 4. Enable npm
	enableCmd := exec.Command(bin, "enable", "npm")
	enableCmd.Env = env
	out, err = enableCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("enable npm failed: %v, out: %s", err, string(out))
	}
	if !strings.Contains(string(out), "InstallGate enabled for npm") {
		t.Errorf("unexpected enable output: %s", string(out))
	}

	// Check .npmrc content
	enabledBytes, err := os.ReadFile(npmrcPath)
	if err != nil {
		t.Fatal(err)
	}
	expectedReg := fmt.Sprintf("registry=http://127.0.0.1:%d/", port)
	if !strings.Contains(string(enabledBytes), expectedReg) {
		t.Errorf("enabled .npmrc missing registry: %s", string(enabledBytes))
	}

	// 5. Status after enable
	statusCmd2 := exec.Command(bin, "status")
	statusCmd2.Env = env
	out, err = statusCmd2.CombinedOutput()
	if err != nil {
		t.Fatalf("status failed: %v, out: %s", err, string(out))
	}
	if !strings.Contains(string(out), "npm registry:     enabled") {
		t.Errorf("status should be enabled: %s", string(out))
	}

	// 6. Disable npm
	disableCmd := exec.Command(bin, "disable", "npm")
	disableCmd.Env = env
	out, err = disableCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("disable npm failed: %v, out: %s", err, string(out))
	}
	if !strings.Contains(string(out), "InstallGate disabled for npm") {
		t.Errorf("unexpected disable output: %s", string(out))
	}

	// 7. Verify .npmrc was restored byte-for-byte
	restoredBytes, err := os.ReadFile(npmrcPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restoredBytes, originalContent) {
		t.Fatalf("restoration not byte-for-byte identical:\ngot:\n%s\nwant:\n%s", string(restoredBytes), string(originalContent))
	}

	// 8. Status after disable
	statusCmd3 := exec.Command(bin, "status")
	statusCmd3.Env = env
	out, err = statusCmd3.CombinedOutput()
	if err != nil {
		t.Fatalf("status failed: %v, out: %s", err, string(out))
	}
	if !strings.Contains(string(out), "npm registry:     disabled") {
		t.Errorf("status should be disabled after disable: %s", string(out))
	}
}

func TestCLI_ApprovalsAndAudit(t *testing.T) {
	bin := buildBinary(t)
	dataDir := t.TempDir()
	env := append(os.Environ(), "INSTALLGATE_DATA_DIR="+dataDir)

	// 1. Create approval
	approveCmd := exec.Command(bin, "approve", "express", "--version", "4.18.2", "--reason", "audited safe", "--duration", "48h")
	approveCmd.Env = env
	out, err := approveCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("approve failed: %v\noutput: %s", err, string(out))
	}
	if !strings.Contains(string(out), "Approval created:") || !strings.Contains(string(out), "express@4.18.2") {
		t.Fatalf("unexpected approve output: %s", string(out))
	}

	// 2. List approvals (human table)
	listCmd := exec.Command(bin, "approvals")
	listCmd.Env = env
	out, err = listCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("approvals list failed: %v\noutput: %s", err, string(out))
	}
	if !strings.Contains(string(out), "express") || !strings.Contains(string(out), "audited safe") {
		t.Fatalf("unexpected approvals list: %s", string(out))
	}

	// 3. List approvals (JSON)
	jsonCmd := exec.Command(bin, "approvals", "--json")
	jsonCmd.Env = env
	out, err = jsonCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("approvals --json failed: %v\noutput: %s", err, string(out))
	}
	var apps []map[string]any
	if err := json.Unmarshal(out, &apps); err != nil || len(apps) != 1 {
		t.Fatalf("failed unmarshaling approvals JSON: %v (len=%d)", err, len(apps))
	}
	appID, _ := apps[0]["id"].(string)
	if appID == "" {
		t.Fatal("missing approval id in JSON output")
	}

	// 4. View audit trail (human and JSON)
	auditCmd := exec.Command(bin, "audit")
	auditCmd.Env = env
	out, err = auditCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("audit failed: %v\noutput: %s", err, string(out))
	}
	if !strings.Contains(string(out), "approval_created") {
		t.Fatalf("audit output missing approval_created: %s", string(out))
	}

	auditJSONCmd := exec.Command(bin, "audit", "--json")
	auditJSONCmd.Env = env
	out, err = auditJSONCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("audit --json failed: %v\noutput: %s", err, string(out))
	}
	var auditEvents []map[string]any
	if err := json.Unmarshal(out, &auditEvents); err != nil || len(auditEvents) == 0 {
		t.Fatalf("failed unmarshaling audit JSON: %v (len=%d)", err, len(auditEvents))
	}

	// 5. Revoke approval
	revokeCmd := exec.Command(bin, "revoke", appID)
	revokeCmd.Env = env
	out, err = revokeCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("revoke failed: %v\noutput: %s", err, string(out))
	}
	if !strings.Contains(string(out), "revoked") {
		t.Fatalf("unexpected revoke output: %s", string(out))
	}

	// 6. Verify revoked status in listing
	listAfterRevoke := exec.Command(bin, "approvals")
	listAfterRevoke.Env = env
	out, err = listAfterRevoke.CombinedOutput()
	if err != nil {
		t.Fatalf("approvals list failed: %v\noutput: %s", err, string(out))
	}
	if !strings.Contains(string(out), "[revoked]") {
		t.Fatalf("expected revoked status: %s", string(out))
	}
}

func TestCLI_BackupRestoreAndCache(t *testing.T) {
	bin := buildBinary(t)
	dataDir := t.TempDir()
	backupDir := t.TempDir()
	backupFile := filepath.Join(backupDir, "ig_backup.db")
	env := append(os.Environ(), "INSTALLGATE_DATA_DIR="+dataDir)

	// Create an approval to populate database
	approveCmd := exec.Command(bin, "approve", "lodash", "--version", "4.17.21", "--reason", "cli backup test")
	approveCmd.Env = env
	out, err := approveCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("approve failed: %v\noutput: %s", err, string(out))
	}

	// Backup database
	backupCmd := exec.Command(bin, "backup", backupFile)
	backupCmd.Env = env
	out, err = backupCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("backup failed: %v\noutput: %s", err, string(out))
	}
	if !strings.Contains(string(out), "Database backup written") {
		t.Fatalf("unexpected backup output: %s", string(out))
	}
	if _, err := os.Stat(backupFile); err != nil {
		t.Fatalf("backup file not created: %v", err)
	}

	// Cache operations
	cacheClearCmd := exec.Command(bin, "cache", "clear")
	cacheClearCmd.Env = env
	out, err = cacheClearCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("cache clear failed: %v\noutput: %s", err, string(out))
	}
	if !strings.Contains(string(out), "cleared") {
		t.Fatalf("unexpected cache clear output: %s", string(out))
	}

	cacheRebuildCmd := exec.Command(bin, "cache", "rebuild")
	cacheRebuildCmd.Env = env
	out, err = cacheRebuildCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("cache rebuild failed: %v\noutput: %s", err, string(out))
	}
	if !strings.Contains(string(out), "rebuilt") {
		t.Fatalf("unexpected cache rebuild output: %s", string(out))
	}

	// Restore database
	restoreCmd := exec.Command(bin, "restore", backupFile)
	restoreCmd.Env = env
	out, err = restoreCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("restore failed: %v\noutput: %s", err, string(out))
	}
	if !strings.Contains(string(out), "restored") {
		t.Fatalf("unexpected restore output: %s", string(out))
	}

	// Verify approval exists after restore
	listCmd := exec.Command(bin, "approvals")
	listCmd.Env = env
	out, err = listCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("approvals failed after restore: %v\noutput: %s", err, string(out))
	}
	if !strings.Contains(string(out), "lodash") {
		t.Fatalf("restored approval missing: %s", string(out))
	}
}
