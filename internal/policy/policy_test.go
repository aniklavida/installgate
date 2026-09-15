package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aniklavida/installgate/internal/evidence"
	"github.com/aniklavida/installgate/internal/verdict"
)

func TestPolicyBoundsStatement(t *testing.T) {
	statement := PolicyBoundsStatement()
	if statement == "" {
		t.Fatal("bounds statement must not be empty")
	}

	requiredTightenings := []string{"profile", "vulnerability_threshold"}
	for _, req := range requiredTightenings {
		if !strings.Contains(statement, req) {
			t.Errorf("bounds statement must explicitly name tighten capability %q", req)
		}
	}

	requiredInvariants := []string{"Integrity", "malicious", "outage", "reputation", "deterministic"}
	for _, req := range requiredInvariants {
		if !strings.Contains(strings.ToLower(statement), strings.ToLower(req)) {
			t.Errorf("bounds statement must explicitly protect invariant %q", req)
		}
	}

	p := NewDefaultPolicy()
	if p.BoundsStatement() != statement {
		t.Errorf("policy instance BoundsStatement() must match package-level statement")
	}
}

func TestDefaultPolicy(t *testing.T) {
	p := NewDefaultPolicy()
	if p.Version != "1" {
		t.Errorf("expected version 1, got %q", p.Version)
	}
	if p.Profile != Balanced {
		t.Errorf("expected balanced profile, got %q", p.Profile)
	}
	if p.VulnerabilityThreshold != SeverityHigh {
		t.Errorf("expected high vulnerability threshold, got %q", p.VulnerabilityThreshold)
	}
	if err := ValidatePolicy(p); err != nil {
		t.Fatalf("default policy must be valid: %v", err)
	}
}

func TestValidationRejectsMalformedAndOutOfBoundsFiles(t *testing.T) {
	tests := []struct {
		name          string
		yamlContent   string
		expectedField string
	}{
		{
			name:          "empty content",
			yamlContent:   "",
			expectedField: "version",
		},
		{
			name:          "whitespace only",
			yamlContent:   "   \n  \t  \n",
			expectedField: "version",
		},
		{
			name:          "missing version",
			yamlContent:   "profile: balanced\nvulnerability_threshold: high\n",
			expectedField: "version",
		},
		{
			name:          "unsupported version",
			yamlContent:   "version: \"2\"\nprofile: balanced\nvulnerability_threshold: high\n",
			expectedField: "version",
		},
		{
			name:          "invalid profile permissive",
			yamlContent:   "version: \"1\"\nprofile: permissive\nvulnerability_threshold: high\n",
			expectedField: "profile",
		},
		{
			name:          "invalid profile empty",
			yamlContent:   "version: \"1\"\nprofile: \"\"\nvulnerability_threshold: high\n",
			expectedField: "profile",
		},
		{
			name:          "invalid vulnerability threshold off",
			yamlContent:   "version: \"1\"\nprofile: balanced\nvulnerability_threshold: off\n",
			expectedField: "vulnerability_threshold",
		},
		{
			name:          "invalid vulnerability threshold none",
			yamlContent:   "version: \"1\"\nprofile: balanced\nvulnerability_threshold: none\n",
			expectedField: "vulnerability_threshold",
		},
		{
			name:          "invalid vulnerability threshold empty",
			yamlContent:   "version: \"1\"\nprofile: balanced\nvulnerability_threshold: \"\"\n",
			expectedField: "vulnerability_threshold",
		},
		{
			name:          "unknown extra field",
			yamlContent:   "version: \"1\"\nprofile: balanced\nvulnerability_threshold: high\nunsupported_setting: true\n",
			expectedField: "unsupported_setting",
		},
		{
			name:          "forbidden loosening allow_malicious",
			yamlContent:   "version: \"1\"\nprofile: balanced\nvulnerability_threshold: high\nallow_malicious: true\n",
			expectedField: "allow_malicious",
		},
		{
			name:          "forbidden loosening ignore_integrity",
			yamlContent:   "version: \"1\"\nprofile: balanced\nvulnerability_threshold: high\nignore_integrity: true\n",
			expectedField: "ignore_integrity",
		},
		{
			name:          "forbidden loosening ignore_outages",
			yamlContent:   "version: \"1\"\nprofile: balanced\nvulnerability_threshold: high\nignore_outages: true\n",
			expectedField: "ignore_outages",
		},
		{
			name:          "forbidden loosening reputation block",
			yamlContent:   "version: \"1\"\nprofile: balanced\nvulnerability_threshold: high\nreputation: block\n",
			expectedField: "reputation",
		},
		{
			name:          "forbidden loosening low_popularity block",
			yamlContent:   "version: \"1\"\nprofile: balanced\nvulnerability_threshold: high\nlow_popularity: block\n",
			expectedField: "low_popularity",
		},
		{
			name:          "malformed yaml syntax",
			yamlContent:   "version: [unclosed bracket",
			expectedField: "malformed policy YAML",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePolicy([]byte(tt.yamlContent))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.expectedField)
			}
			if !strings.Contains(err.Error(), tt.expectedField) {
				t.Fatalf("expected error to name offending field %q, got: %v", tt.expectedField, err)
			}
		})
	}
}

func TestValidPolicyConfigurations(t *testing.T) {
	tests := []struct {
		name       string
		yaml       string
		wantProf   Profile
		wantThresh Severity
	}{
		{
			name:       "default balanced with high threshold",
			yaml:       "version: \"1\"\nprofile: balanced\nvulnerability_threshold: high\n",
			wantProf:   Balanced,
			wantThresh: SeverityHigh,
		},
		{
			name:       "strict with critical threshold",
			yaml:       "version: \"1\"\nprofile: strict\nvulnerability_threshold: critical\n",
			wantProf:   Strict,
			wantThresh: SeverityCritical,
		},
		{
			name:       "balanced tightened to medium threshold",
			yaml:       "version: \"1\"\nprofile: balanced\nvulnerability_threshold: medium\n",
			wantProf:   Balanced,
			wantThresh: SeverityMedium,
		},
		{
			name:       "strict tightened to low threshold",
			yaml:       "version: \"1\"\nprofile: strict\nvulnerability_threshold: low\n",
			wantProf:   Strict,
			wantThresh: SeverityLow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := ParsePolicy([]byte(tt.yaml))
			if err != nil {
				t.Fatalf("unexpected validation failure: %v", err)
			}
			if p.Profile != tt.wantProf {
				t.Errorf("profile = %q, want %q", p.Profile, tt.wantProf)
			}
			if p.VulnerabilityThreshold != tt.wantThresh {
				t.Errorf("vulnerability_threshold = %q, want %q", p.VulnerabilityThreshold, tt.wantThresh)
			}
		})
	}
}

func TestLoadPolicyFileFromDisk(t *testing.T) {
	tempDir := t.TempDir()
	policyPath := filepath.Join(tempDir, "installgate.yaml")

	content := "version: \"1\"\nprofile: strict\nvulnerability_threshold: medium\n"
	if err := os.WriteFile(policyPath, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write test policy file: %v", err)
	}

	p, err := LoadPolicyFile(policyPath)
	if err != nil {
		t.Fatalf("failed to load policy file: %v", err)
	}

	if p.Profile != Strict {
		t.Errorf("profile = %q, want %q", p.Profile, Strict)
	}
	if p.VulnerabilityThreshold != SeverityMedium {
		t.Errorf("threshold = %q, want %q", p.VulnerabilityThreshold, SeverityMedium)
	}

	// Loading non-existent file returns error
	_, err = LoadPolicyFile(filepath.Join(tempDir, "nonexistent.yaml"))
	if err == nil {
		t.Fatal("expected error loading nonexistent policy file, got nil")
	}
}

func TestLoadDefaultPolicyInDirectory(t *testing.T) {
	tempDir := t.TempDir()

	// When no file exists, returns default policy
	p, err := LoadDefaultPolicy(tempDir)
	if err != nil {
		t.Fatalf("unexpected error loading default policy: %v", err)
	}
	if p.Profile != Balanced || p.VulnerabilityThreshold != SeverityHigh {
		t.Errorf("expected default policy, got %+v", p)
	}

	// When installgate.yaml exists, loads it
	policyPath := filepath.Join(tempDir, "installgate.yaml")
	content := "version: \"1\"\nprofile: strict\nvulnerability_threshold: low\n"
	if err := os.WriteFile(policyPath, []byte(content), 0o600); err != nil {
		t.Fatalf("failed to write policy: %v", err)
	}

	p, err = LoadDefaultPolicy(tempDir)
	if err != nil {
		t.Fatalf("unexpected error loading installgate.yaml: %v", err)
	}
	if p.Profile != Strict || p.VulnerabilityThreshold != SeverityLow {
		t.Errorf("expected loaded policy, got %+v", p)
	}
}

func TestRepositoryPolicyFileIsValid(t *testing.T) {
	// Assert that the repository's root installgate.yaml is valid
	repoRoot := filepath.Join("..", "..")
	rootPolicy := filepath.Join(repoRoot, "installgate.yaml")

	p, err := LoadPolicyFile(rootPolicy)
	if err != nil {
		t.Fatalf("repository root installgate.yaml must be valid: %v", err)
	}
	if p.Version != "1" {
		t.Errorf("expected version 1, got %q", p.Version)
	}
	if p.Profile != Balanced {
		t.Errorf("expected balanced profile, got %q", p.Profile)
	}
	if p.VulnerabilityThreshold != SeverityHigh {
		t.Errorf("expected high threshold, got %q", p.VulnerabilityThreshold)
	}
}

func TestConfigurableThresholdSnapshotEvaluation(t *testing.T) {
	baseTime := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)

	// Snapshot with medium severity vulnerability
	obs := []verdict.Signal{
		{
			Kind:        evidence.KindVulnerability,
			Source:      "osv",
			Observation: "medium",
			Confidence:  evidence.ConfidenceHigh,
			RetrievedAt: baseTime,
			FreshUntil:  baseTime.Add(1 * time.Hour),
		},
	}
	states := map[string]evidence.State{
		evidence.KindVulnerability: evidence.StateAvailable,
	}
	snap := evidence.NewSnapshot("test-pkg", "1.0.0", obs, states, baseTime)

	// Default policy (high threshold) allows medium vulnerability
	defaultPol := NewDefaultPolicy()
	decDefault := defaultPol.EvaluateSnapshot(snap)
	if decDefault.Verdict != verdict.Allow {
		t.Errorf("default policy (high) should allow medium vulnerability, got %q", decDefault.Verdict)
	}

	// Tightened policy (medium threshold) blocks medium vulnerability
	tightPol := &Policy{
		Version:                "1",
		Profile:                Balanced,
		VulnerabilityThreshold: SeverityMedium,
	}
	decTight := tightPol.EvaluateSnapshot(snap)
	if decTight.Verdict != verdict.Block {
		t.Errorf("tightened policy (medium) should block medium vulnerability, got %q", decTight.Verdict)
	}
	if len(decTight.Reasons) == 0 || decTight.Reasons[0].RuleID != "core.vulnerability-threshold" {
		t.Errorf("expected core.vulnerability-threshold rule, got %+v", decTight.Reasons)
	}
}
