package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
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
