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

func TestCLI_Check_HumanAndJSON(t *testing.T) {
	bin := buildBinary(t)
	dataDir := t.TempDir()
	env := append(os.Environ(), "INSTALLGATE_DATA_DIR="+dataDir)

	// 1. Check clean package human output
	checkCmd := exec.Command(bin, "check", "left-pad@1.3.0")
	checkCmd.Env = env
	out, err := checkCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("check failed: %v\noutput: %s", err, string(out))
	}
	outStr := string(out)
	if !strings.Contains(outStr, "InstallGate Decision: ALLOWED") {
		t.Errorf("expected ALLOWED in human check output: %s", outStr)
	}
	if !strings.Contains(outStr, "left-pad@1.3.0") {
		t.Errorf("expected package@version in output: %s", outStr)
	}

	// 2. Check clean package JSON output
	checkJSONCmd := exec.Command(bin, "check", "left-pad@1.3.0", "--json")
	checkJSONCmd.Env = env
	jsonOut, err := checkJSONCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("check --json failed: %v\noutput: %s", err, string(jsonOut))
	}
	doc, err := explanation.ParseJSON(jsonOut)
	if err != nil {
		t.Fatalf("failed parsing check JSON output: %v\noutput: %s", err, string(jsonOut))
	}
	if doc.Package != "left-pad" || doc.Version != "1.3.0" {
		t.Errorf("doc package@version = %s@%s, want left-pad@1.3.0", doc.Package, doc.Version)
	}
	if doc.Verdict != verdict.Allow {
		t.Errorf("doc verdict = %q, want allow", doc.Verdict)
	}

	// 3. Check with --version flag format
	checkPkg2 := exec.Command(bin, "check", "express", "--version", "4.18.2", "--json")
	checkPkg2.Env = env
	pkg2JSONOut, err := checkPkg2.CombinedOutput()
	if err != nil {
		t.Fatalf("check with --version failed: %v\noutput: %s", err, string(pkg2JSONOut))
	}
	doc2, err := explanation.ParseJSON(pkg2JSONOut)
	if err != nil {
		t.Fatalf("failed parsing check JSON output: %v\noutput: %s", err, string(pkg2JSONOut))
	}
	if doc2.Package != "express" || doc2.Version != "4.18.2" {
		t.Errorf("doc package@version = %s@%s, want express@4.18.2", doc2.Package, doc2.Version)
	}
	if doc2.Verdict != verdict.Allow {
		t.Errorf("doc2 verdict = %q, want allow", doc2.Verdict)
	}
}

func TestCLI_Deny_HumanAndJSON(t *testing.T) {
	bin := buildBinary(t)
	dataDir := t.TempDir()
	env := append(os.Environ(), "INSTALLGATE_DATA_DIR="+dataDir)

	// Create an active approval
	approveCmd := exec.Command(bin, "approve", "suspect-pkg", "--version", "1.0.0", "--reason", "tentative approval")
	approveCmd.Env = env
	if out, err := approveCmd.CombinedOutput(); err != nil {
		t.Fatalf("approve failed: %v\noutput: %s", err, string(out))
	}

	// 1. Run deny human output
	denyCmd := exec.Command(bin, "deny", "suspect-pkg", "--version", "1.0.0", "--reason", "malware confirmed")
	denyCmd.Env = env
	denyOut, err := denyCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("deny failed: %v\noutput: %s", err, string(denyOut))
	}
	denyStr := string(denyOut)
	if !strings.Contains(denyStr, "Denial recorded: suspect-pkg@1.0.0") {
		t.Errorf("unexpected deny output: %s", denyStr)
	}
	if !strings.Contains(denyStr, "Revoked 1 active approval(s)") {
		t.Errorf("expected revoked active approval in deny output: %s", denyStr)
	}

	// Verify approval list shows no active approvals
	listCmd := exec.Command(bin, "approvals", "--active", "--json")
	listCmd.Env = env
	listOut, err := listCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("approvals list failed: %v\noutput: %s", err, string(listOut))
	}
	var activeApps []map[string]any
	if err := json.Unmarshal(listOut, &activeApps); err != nil {
		t.Fatalf("failed unmarshaling active approvals: %v", err)
	}
	if len(activeApps) != 0 {
		t.Errorf("expected 0 active approvals, got %d", len(activeApps))
	}

	// 2. Run deny JSON output
	denyJSONCmd := exec.Command(bin, "deny", "malicious-lib@3.0.0", "--reason", "known cve", "--json")
	denyJSONCmd.Env = env
	denyJSONOut, err := denyJSONCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("deny --json failed: %v\noutput: %s", err, string(denyJSONOut))
	}
	var denyMap map[string]any
	if err := json.Unmarshal(denyJSONOut, &denyMap); err != nil {
		t.Fatalf("failed unmarshaling deny JSON: %v\noutput: %s", err, string(denyJSONOut))
	}
	if denyMap["action"] != "deny" || denyMap["package"] != "malicious-lib" || denyMap["version"] != "3.0.0" {
		t.Errorf("unexpected deny JSON fields: %+v", denyMap)
	}
	if denyMap["verdict"] != "block" {
		t.Errorf("unexpected verdict in deny JSON: %v", denyMap["verdict"])
	}

	// 3. Verify audit trail contains decision_denied events
	auditCmd := exec.Command(bin, "audit", "--json")
	auditCmd.Env = env
	auditOut, err := auditCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("audit --json failed: %v\noutput: %s", err, string(auditOut))
	}
	var auditList []map[string]any
	if err := json.Unmarshal(auditOut, &auditList); err != nil {
		t.Fatalf("failed unmarshaling audit JSON: %v", err)
	}
	var foundDenied bool
	for _, ev := range auditList {
		if ev["event_type"] == "decision_denied" && ev["package"] == "suspect-pkg" {
			foundDenied = true
			break
		}
	}
	if !foundDenied {
		t.Errorf("decision_denied audit event not found for suspect-pkg in audit trail: %s", string(auditOut))
	}
}

func TestCLI_Policy_HumanAndJSON(t *testing.T) {
	bin := buildBinary(t)
	tempDir := t.TempDir()

	// 1. Policy show human
	showCmd := exec.Command(bin, "policy")
	showCmd.Dir = tempDir
	out, err := showCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("policy failed: %v\noutput: %s", err, string(out))
	}
	outStr := string(out)
	if !strings.Contains(outStr, "InstallGate Policy:") || !strings.Contains(outStr, "Profile:                 balanced") {
		t.Errorf("unexpected policy show output: %s", outStr)
	}

	// 2. Policy show JSON
	showJSONCmd := exec.Command(bin, "policy", "--json")
	showJSONCmd.Dir = tempDir
	jsonOut, err := showJSONCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("policy --json failed: %v\noutput: %s", err, string(jsonOut))
	}
	var polMap map[string]any
	if err := json.Unmarshal(jsonOut, &polMap); err != nil {
		t.Fatalf("failed unmarshaling policy JSON: %v\noutput: %s", err, string(jsonOut))
	}
	if polMap["profile"] != "balanced" || polMap["version"] != "1" {
		t.Errorf("unexpected policy fields: %+v", polMap)
	}

	// 3. Policy bounds human and JSON
	boundsCmd := exec.Command(bin, "policy", "bounds")
	boundsOut, err := boundsCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("policy bounds failed: %v\noutput: %s", err, string(boundsOut))
	}
	if !strings.Contains(string(boundsOut), "InstallGate repository policy bounds") {
		t.Errorf("unexpected policy bounds output: %s", string(boundsOut))
	}

	boundsJSONCmd := exec.Command(bin, "policy", "bounds", "--json")
	boundsJSONOut, err := boundsJSONCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("policy bounds --json failed: %v\noutput: %s", err, string(boundsJSONOut))
	}
	var boundsMap map[string]string
	if err := json.Unmarshal(boundsJSONOut, &boundsMap); err != nil || !strings.Contains(boundsMap["bounds"], "InstallGate repository policy bounds") {
		t.Errorf("unexpected policy bounds JSON: %v", boundsMap)
	}

	// 4. Policy validate valid file
	validYAML := `version: "1"
profile: "strict"
vulnerability_threshold: "low"
`
	validPath := filepath.Join(tempDir, "installgate.yaml")
	if err := os.WriteFile(validPath, []byte(validYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	valCmd := exec.Command(bin, "policy", "validate", validPath)
	valOut, err := valCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("policy validate failed: %v\noutput: %s", err, string(valOut))
	}
	if !strings.Contains(string(valOut), "is valid") {
		t.Errorf("unexpected validate output: %s", string(valOut))
	}

	valJSONCmd := exec.Command(bin, "policy", "validate", validPath, "--json")
	valJSONOut, err := valJSONCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("policy validate --json failed: %v\noutput: %s", err, string(valJSONOut))
	}
	var valMap map[string]any
	if err := json.Unmarshal(valJSONOut, &valMap); err != nil || valMap["valid"] != true {
		t.Errorf("unexpected validate JSON output: %+v", valMap)
	}

	// 5. Policy validate invalid file
	invalidYAML := `version: "2"
profile: "unsupported-profile"
`
	invalidPath := filepath.Join(tempDir, "invalid.yaml")
	if err := os.WriteFile(invalidPath, []byte(invalidYAML), 0o644); err != nil {
		t.Fatal(err)
	}

	invCmd := exec.Command(bin, "policy", "validate", invalidPath)
	invOut, err := invCmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected validation failure for invalid policy file, got nil\noutput: %s", string(invOut))
	}

	invJSONCmd := exec.Command(bin, "policy", "validate", invalidPath, "--json")
	invJSONOut, err := invJSONCmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected validation failure exit code for invalid policy JSON, got nil\noutput: %s", string(invJSONOut))
	}
	var invMap map[string]any
	if err := json.Unmarshal(invJSONOut, &invMap); err != nil || invMap["valid"] != false {
		t.Errorf("unexpected invalid validate JSON: %+v", invMap)
	}
}

func TestCLI_DryRun_AllMutatingCommands(t *testing.T) {
	bin := buildBinary(t)
	baseDir := t.TempDir()
	dataDir := filepath.Join(baseDir, "data")
	env := append(os.Environ(), "INSTALLGATE_DATA_DIR="+dataDir)

	// 1. init --dry-run: data directory must NOT be created
	initDry := exec.Command(bin, "init", "--dry-run")
	initDry.Env = env
	out, err := initDry.CombinedOutput()
	if err != nil {
		t.Fatalf("init --dry-run failed: %v\noutput: %s", err, string(out))
	}
	if !strings.Contains(string(out), "[dry-run]") {
		t.Errorf("init --dry-run missing [dry-run] tag: %s", string(out))
	}
	if _, err := os.Stat(dataDir); !os.IsNotExist(err) {
		t.Errorf("init --dry-run created data directory: %s", dataDir)
	}

	// Actually initialize now so subsequent tests have a valid data dir when needed
	initReal := exec.Command(bin, "init")
	initReal.Env = env
	if out, err := initReal.CombinedOutput(); err != nil {
		t.Fatalf("init failed: %v\noutput: %s", err, string(out))
	}

	// 2. enable npm --dry-run: .npmrc must NOT be modified
	npmrcPath := filepath.Join(baseDir, ".npmrc")
	initialNpmrc := []byte("registry=https://registry.npmjs.org/\n")
	if err := os.WriteFile(npmrcPath, initialNpmrc, 0o644); err != nil {
		t.Fatal(err)
	}
	enableEnv := append(env, "NPM_CONFIG_USERCONFIG="+npmrcPath)
	enableDry := exec.Command(bin, "enable", "npm", "--dry-run")
	enableDry.Env = enableEnv
	out, err = enableDry.CombinedOutput()
	if err != nil {
		t.Fatalf("enable --dry-run failed: %v\noutput: %s", err, string(out))
	}
	if !strings.Contains(string(out), "[dry-run]") {
		t.Errorf("enable --dry-run missing [dry-run] tag: %s", string(out))
	}
	content, _ := os.ReadFile(npmrcPath)
	if !bytes.Equal(content, initialNpmrc) {
		t.Errorf("enable --dry-run modified .npmrc:\ngot:  %s\nwant: %s", string(content), string(initialNpmrc))
	}

	// 3. disable npm --dry-run: .npmrc must NOT be modified
	disableDry := exec.Command(bin, "disable", "npm", "--dry-run")
	disableDry.Env = enableEnv
	out, err = disableDry.CombinedOutput()
	if err != nil {
		t.Fatalf("disable --dry-run failed: %v\noutput: %s", err, string(out))
	}
	if !strings.Contains(string(out), "[dry-run]") {
		t.Errorf("disable --dry-run missing [dry-run] tag: %s", string(out))
	}
	content, _ = os.ReadFile(npmrcPath)
	if !bytes.Equal(content, initialNpmrc) {
		t.Errorf("disable --dry-run modified .npmrc:\ngot:  %s\nwant: %s", string(content), string(initialNpmrc))
	}

	// 4. approve --dry-run: no approval created in store
	approveDry := exec.Command(bin, "approve", "pkg-a", "--version", "1.0.0", "--dry-run")
	approveDry.Env = env
	out, err = approveDry.CombinedOutput()
	if err != nil {
		t.Fatalf("approve --dry-run failed: %v\noutput: %s", err, string(out))
	}
	if !strings.Contains(string(out), "[dry-run]") {
		t.Errorf("approve --dry-run missing [dry-run] tag: %s", string(out))
	}
	approveJSONDry := exec.Command(bin, "approve", "pkg-a", "--version", "1.0.0", "--dry-run", "--json")
	approveJSONDry.Env = env
	outJSON, err := approveJSONDry.CombinedOutput()
	if err != nil {
		t.Fatalf("approve --dry-run --json failed: %v\noutput: %s", err, string(outJSON))
	}
	var appJSONMap map[string]any
	if err := json.Unmarshal(outJSON, &appJSONMap); err != nil || appJSONMap["dry_run"] != true {
		t.Errorf("unexpected approve --dry-run JSON: %s", string(outJSON))
	}
	listCmd := exec.Command(bin, "approvals", "--json")
	listCmd.Env = env
	out, _ = listCmd.CombinedOutput()
	var apps []any
	_ = json.Unmarshal(out, &apps)
	if len(apps) != 0 {
		t.Errorf("approve --dry-run created an approval in store: %s", string(out))
	}

	// 5. deny --dry-run: no audit or denial persisted
	denyDry := exec.Command(bin, "deny", "pkg-b", "--version", "1.0.0", "--dry-run")
	denyDry.Env = env
	out, err = denyDry.CombinedOutput()
	if err != nil {
		t.Fatalf("deny --dry-run failed: %v\noutput: %s", err, string(out))
	}
	if !strings.Contains(string(out), "[dry-run]") {
		t.Errorf("deny --dry-run missing [dry-run] tag: %s", string(out))
	}
	denyJSONDry := exec.Command(bin, "deny", "pkg-b", "--version", "1.0.0", "--dry-run", "--json")
	denyJSONDry.Env = env
	outJSON, err = denyJSONDry.CombinedOutput()
	if err != nil {
		t.Fatalf("deny --dry-run --json failed: %v\noutput: %s", err, string(outJSON))
	}
	var denyJSONMap map[string]any
	if err := json.Unmarshal(outJSON, &denyJSONMap); err != nil || denyJSONMap["dry_run"] != true {
		t.Errorf("unexpected deny --dry-run JSON: %s", string(outJSON))
	}
	auditCmd := exec.Command(bin, "audit", "--json")
	auditCmd.Env = env
	out, _ = auditCmd.CombinedOutput()
	if strings.Contains(string(out), "pkg-b") {
		t.Errorf("deny --dry-run recorded audit event in store: %s", string(out))
	}

	// 6. revoke --dry-run: prints [dry-run]
	revokeDry := exec.Command(bin, "revoke", "fake-id", "--dry-run")
	revokeDry.Env = env
	out, err = revokeDry.CombinedOutput()
	if err != nil {
		t.Fatalf("revoke --dry-run failed: %v\noutput: %s", err, string(out))
	}
	if !strings.Contains(string(out), "[dry-run]") {
		t.Errorf("revoke --dry-run missing [dry-run] tag: %s", string(out))
	}

	// 7. cache clear --dry-run
	cacheClearDry := exec.Command(bin, "cache", "clear", "--dry-run")
	cacheClearDry.Env = env
	out, err = cacheClearDry.CombinedOutput()
	if err != nil {
		t.Fatalf("cache clear --dry-run failed: %v\noutput: %s", err, string(out))
	}
	if !strings.Contains(string(out), "[dry-run]") {
		t.Errorf("cache clear --dry-run missing [dry-run] tag: %s", string(out))
	}

	// 8. cache rebuild --dry-run
	cacheRebuildDry := exec.Command(bin, "cache", "rebuild", "--dry-run")
	cacheRebuildDry.Env = env
	out, err = cacheRebuildDry.CombinedOutput()
	if err != nil {
		t.Fatalf("cache rebuild --dry-run failed: %v\noutput: %s", err, string(out))
	}
	if !strings.Contains(string(out), "[dry-run]") {
		t.Errorf("cache rebuild --dry-run missing [dry-run] tag: %s", string(out))
	}

	// 9. backup --dry-run: target file must NOT be created
	backupDest := filepath.Join(baseDir, "backup-dryrun.db")
	backupDry := exec.Command(bin, "backup", backupDest, "--dry-run")
	backupDry.Env = env
	out, err = backupDry.CombinedOutput()
	if err != nil {
		t.Fatalf("backup --dry-run failed: %v\noutput: %s", err, string(out))
	}
	if !strings.Contains(string(out), "[dry-run]") {
		t.Errorf("backup --dry-run missing [dry-run] tag: %s", string(out))
	}
	if _, err := os.Stat(backupDest); !os.IsNotExist(err) {
		t.Errorf("backup --dry-run created backup file: %s", backupDest)
	}

	// 10. restore --dry-run: create a valid backup file to test restore --dry-run
	realBackup := filepath.Join(baseDir, "real-backup.db")
	backupCmd := exec.Command(bin, "backup", realBackup)
	backupCmd.Env = env
	if out, err := backupCmd.CombinedOutput(); err != nil {
		t.Fatalf("real backup failed: %v\noutput: %s", err, string(out))
	}
	restoreDry := exec.Command(bin, "restore", realBackup, "--dry-run")
	restoreDry.Env = env
	out, err = restoreDry.CombinedOutput()
	if err != nil {
		t.Fatalf("restore --dry-run failed: %v\noutput: %s", err, string(out))
	}
	if !strings.Contains(string(out), "[dry-run]") {
		t.Errorf("restore --dry-run missing [dry-run] tag: %s", string(out))
	}

	// 11. start --dry-run: no PID file must be created
	startDry := exec.Command(bin, "start", "--dry-run")
	startDry.Env = env
	out, err = startDry.CombinedOutput()
	if err != nil {
		t.Fatalf("start --dry-run failed: %v\noutput: %s", err, string(out))
	}
	if !strings.Contains(string(out), "[dry-run]") {
		t.Errorf("start --dry-run missing [dry-run] tag: %s", string(out))
	}
	pidFile := filepath.Join(dataDir, "installgate.pid")
	if _, err := os.Stat(pidFile); !os.IsNotExist(err) {
		t.Errorf("start --dry-run created PID file: %s", pidFile)
	}

	// 12. stop --dry-run: prints [dry-run]
	stopDry := exec.Command(bin, "stop", "--dry-run")
	stopDry.Env = env
	out, err = stopDry.CombinedOutput()
	if err != nil {
		t.Fatalf("stop --dry-run failed: %v\noutput: %s", err, string(out))
	}
	if !strings.Contains(string(out), "[dry-run]") {
		t.Errorf("stop --dry-run missing [dry-run] tag: %s", string(out))
	}
}
