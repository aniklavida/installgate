package explanation

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aniklavida/installgate/internal/evidence"
	"github.com/aniklavida/installgate/internal/policy"
	"github.com/aniklavida/installgate/internal/verdict"
)

var updateGolden = flag.Bool("update", false, "update golden test files")

func TestGoldenRenderings(t *testing.T) {
	fixedTime := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	goldenDir := filepath.Join("testdata", "golden")

	tests := []struct {
		name      string
		pkg       string
		version   string
		signals   []verdict.Signal
		states    map[string]evidence.State
		profile   policy.Profile
		threshold policy.Severity
	}{
		{
			name:    "blocked_vulnerability",
			pkg:     "express",
			version: "4.18.2",
			signals: []verdict.Signal{
				{
					Kind:        evidence.KindVulnerability,
					Source:      "osv",
					Observation: "critical",
					Confidence:  evidence.ConfidenceHigh,
					RetrievedAt: fixedTime,
					FreshUntil:  fixedTime.Add(1 * time.Hour),
				},
				{
					Kind:        evidence.KindVulnerability,
					Source:      "osv",
					Observation: "safe_version_suggested:4.18.3",
					Confidence:  evidence.ConfidenceHigh,
					RetrievedAt: fixedTime,
					FreshUntil:  fixedTime.Add(1 * time.Hour),
				},
			},
			states: map[string]evidence.State{
				evidence.KindVulnerability: evidence.StateAvailable,
			},
			profile:   policy.Balanced,
			threshold: policy.SeverityHigh,
		},
		{
			name:    "blocked_integrity",
			pkg:     "left-pad",
			version: "1.3.0",
			signals: []verdict.Signal{
				{
					Kind:        evidence.KindIntegrity,
					Source:      "npm_registry",
					Observation: "mismatch",
					Confidence:  evidence.ConfidenceHigh,
					RetrievedAt: fixedTime,
					FreshUntil:  fixedTime.Add(24 * time.Hour),
				},
			},
			states: map[string]evidence.State{
				evidence.KindIntegrity: evidence.StateAvailable,
			},
			profile:   policy.Balanced,
			threshold: policy.SeverityHigh,
		},
		{
			name:    "approval_confusable_fresh",
			pkg:     "re-act",
			version: "0.0.1",
			signals: []verdict.Signal{
				{
					Kind:        evidence.KindNameConfusion,
					Source:      "local_similarity",
					Observation: "confusion_detected:react",
					Confidence:  evidence.ConfidenceHigh,
					RetrievedAt: fixedTime,
					FreshUntil:  fixedTime.Add(12 * time.Hour),
				},
				{
					Kind:        evidence.KindPackageAge,
					Source:      "npm_registry",
					Observation: "fresh",
					Confidence:  evidence.ConfidenceHigh,
					RetrievedAt: fixedTime,
					FreshUntil:  fixedTime.Add(15 * time.Minute),
				},
			},
			states: map[string]evidence.State{
				evidence.KindNameConfusion: evidence.StateAvailable,
				evidence.KindPackageAge:    evidence.StateAvailable,
			},
			profile:   policy.Balanced,
			threshold: policy.SeverityHigh,
		},
		{
			name:    "degraded_outage_approval",
			pkg:     "lodash",
			version: "4.17.21",
			signals: []verdict.Signal{
				{
					Kind:        evidence.KindAvailability,
					Source:      "osv",
					Observation: "unavailable",
					Confidence:  evidence.ConfidenceNone,
					RetrievedAt: fixedTime,
					FreshUntil:  fixedTime,
				},
			},
			states: map[string]evidence.State{
				evidence.KindAvailability: evidence.StateUnavailable,
			},
			profile:   policy.Balanced,
			threshold: policy.SeverityHigh,
		},
		{
			name:    "allowed_policy_satisfied",
			pkg:     "debug",
			version: "4.3.4",
			signals: []verdict.Signal{
				{
					Kind:        evidence.KindVulnerability,
					Source:      "osv",
					Observation: "none",
					Confidence:  evidence.ConfidenceHigh,
					RetrievedAt: fixedTime,
					FreshUntil:  fixedTime.Add(1 * time.Hour),
				},
			},
			states: map[string]evidence.State{
				evidence.KindVulnerability: evidence.StateAvailable,
			},
			profile:   policy.Balanced,
			threshold: policy.SeverityHigh,
		},
		{
			name:    "warn_install_time",
			pkg:     "fsevents",
			version: "2.3.3",
			signals: []verdict.Signal{
				{
					Kind:        evidence.KindInstallScript,
					Source:      "npm_registry",
					Observation: "present",
					Confidence:  evidence.ConfidenceHigh,
					RetrievedAt: fixedTime,
					FreshUntil:  fixedTime.Add(7 * 24 * time.Hour),
				},
			},
			states: map[string]evidence.State{
				evidence.KindInstallScript: evidence.StateAvailable,
			},
			profile:   policy.Balanced,
			threshold: policy.SeverityHigh,
		},
	}

	if *updateGolden {
		if err := os.MkdirAll(goldenDir, 0o755); err != nil {
			t.Fatalf("failed to create golden directory: %v", err)
		}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			snap := evidence.NewSnapshot(tt.pkg, tt.version, tt.signals, tt.states, fixedTime)
			pol := &policy.Policy{
				Version:                "1",
				Profile:                tt.profile,
				VulnerabilityThreshold: tt.threshold,
			}
			dec := pol.EvaluateSnapshot(snap)

			doc, err := NewDecisionDocument(tt.pkg, tt.version, dec, snap, WithReferenceTime(fixedTime))
			if err != nil {
				t.Fatalf("NewDecisionDocument failed: %v", err)
			}

			jsonBytes, err := RenderJSON(doc)
			if err != nil {
				t.Fatalf("RenderJSON failed: %v", err)
			}

			humanStr := RenderHuman(doc)

			jsonPath := filepath.Join(goldenDir, tt.name+".json")
			txtPath := filepath.Join(goldenDir, tt.name+".txt")

			if *updateGolden {
				if err := os.WriteFile(jsonPath, jsonBytes, 0o644); err != nil {
					t.Fatalf("failed to write golden JSON %s: %v", jsonPath, err)
				}
				if err := os.WriteFile(txtPath, []byte(humanStr), 0o644); err != nil {
					t.Fatalf("failed to write golden TXT %s: %v", txtPath, err)
				}
				return
			}

			// Verify against golden JSON
			expectedJSON, err := os.ReadFile(jsonPath)
			if err != nil {
				t.Fatalf("failed to read golden JSON file %s: %v", jsonPath, err)
			}
			if string(jsonBytes) != string(expectedJSON) {
				t.Errorf("JSON output does not match golden file %s:\nGOT:\n%s\nWANT:\n%s", jsonPath, string(jsonBytes), string(expectedJSON))
			}

			// Verify against golden Human TXT
			expectedTXT, err := os.ReadFile(txtPath)
			if err != nil {
				t.Fatalf("failed to read golden TXT file %s: %v", txtPath, err)
			}
			if humanStr != string(expectedTXT) {
				t.Errorf("Human output does not match golden file %s:\nGOT:\n%s\nWANT:\n%s", txtPath, humanStr, string(expectedTXT))
			}
		})
	}
}
