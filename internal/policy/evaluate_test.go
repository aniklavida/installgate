package policy

import (
	"reflect"
	"testing"
	"time"

	"github.com/aniklavida/installgate/internal/evidence"
	"github.com/aniklavida/installgate/internal/verdict"
)

func TestEvaluateMatrix(t *testing.T) {
	tests := []struct {
		name       string
		profile    Profile
		assessment Assessment
		want       verdict.Kind
	}{
		{"integrity always blocks", Balanced, Assessment{IntegrityMismatch: true}, verdict.Block},
		{"vulnerability always blocks", Strict, Assessment{VulnerabilityAboveThreshold: true}, verdict.Block},
		{"confusable fresh balanced asks", Balanced, Assessment{StrongNameConfusion: true, NewbornOrFresh: true}, verdict.ApprovalRequired},
		{"confusable fresh strict blocks", Strict, Assessment{StrongNameConfusion: true, NewbornOrFresh: true}, verdict.Block},
		{"provenance script balanced asks", Balanced, Assessment{PublisherOrProvenanceChanged: true, InstallScriptAdded: true}, verdict.ApprovalRequired},
		{"install script balanced warns", Balanced, Assessment{HasInstallScriptOrNativeBuild: true}, verdict.Warn},
		{"install script strict asks", Strict, Assessment{HasInstallScriptOrNativeBuild: true}, verdict.ApprovalRequired},
		{"outage with fresh cache allows degraded", Balanced, Assessment{EvidenceUnavailable: true, FreshCachedAllow: true}, verdict.Allow},
		{"outage strict with fresh cache asks", Strict, Assessment{EvidenceUnavailable: true, FreshCachedAllow: true}, verdict.ApprovalRequired},
		{"outage strict without cache blocks", Strict, Assessment{EvidenceUnavailable: true}, verdict.Block},
		{"low popularity alone allows", Balanced, Assessment{LowPopularity: true}, verdict.Allow},
		{"no findings allows", Balanced, Assessment{}, verdict.Allow},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Evaluate(tt.profile, tt.assessment)
			if got.Verdict != tt.want {
				t.Fatalf("verdict = %q, want %q", got.Verdict, tt.want)
			}
			if len(got.Reasons) == 0 || got.Reasons[0].RuleID == "" {
				t.Fatal("decision must include an explainable rule")
			}
		})
	}
}

func TestUnavailableEvidenceIsExplicitlyDegraded(t *testing.T) {
	got := Evaluate(Balanced, Assessment{EvidenceUnavailable: true})
	if !got.Degraded {
		t.Fatal("unavailable evidence must mark the decision degraded")
	}
}

func TestEvaluateSnapshotReplay(t *testing.T) {
	baseTime := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	obs := []verdict.Signal{
		{
			Kind:        evidence.KindVulnerability,
			Source:      "osv",
			Observation: "none",
			Confidence:  evidence.ConfidenceHigh,
			RetrievedAt: baseTime,
			FreshUntil:  baseTime.Add(1 * time.Hour),
		},
		{
			Kind:        evidence.KindIntegrity,
			Source:      "npm",
			Observation: "sha512-expected",
			Confidence:  evidence.ConfidenceHigh,
			RetrievedAt: baseTime,
			FreshUntil:  baseTime.Add(24 * time.Hour),
		},
	}
	states := map[string]evidence.State{
		evidence.KindVulnerability: evidence.StateAvailable,
		evidence.KindIntegrity:     evidence.StateAvailable,
	}

	snap := evidence.NewSnapshot("express", "4.18.2", obs, states, baseTime)

	// Replay 10 times: must produce identical verdict, reasons, and rule identifiers every time
	initial := EvaluateSnapshot(Balanced, snap)
	for i := 0; i < 10; i++ {
		replayed := EvaluateSnapshot(Balanced, snap)
		if !reflect.DeepEqual(initial, replayed) {
			t.Fatalf("replay iteration %d produced divergent decision: got %+v, want %+v", i, replayed, initial)
		}
	}
}

func TestEvaluateSnapshotMatrix(t *testing.T) {
	baseTime := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name        string
		profile     Profile
		signals     []verdict.Signal
		states      map[string]evidence.State
		wantVerdict verdict.Kind
		wantRuleID  string
		wantDegrade bool
	}{
		{
			name:    "integrity mismatch blocks",
			profile: Balanced,
			signals: []verdict.Signal{
				{Kind: evidence.KindIntegrity, Observation: "mismatch"},
			},
			wantVerdict: verdict.Block,
			wantRuleID:  "core.integrity-or-malicious",
			wantDegrade: false,
		},
		{
			name:    "vulnerability above threshold blocks",
			profile: Strict,
			signals: []verdict.Signal{
				{Kind: evidence.KindVulnerability, Observation: "above_threshold"},
			},
			wantVerdict: verdict.Block,
			wantRuleID:  "core.vulnerability-threshold",
			wantDegrade: false,
		},
		{
			name:    "unavailable evidence without cache under balanced requires approval",
			profile: Balanced,
			signals: []verdict.Signal{
				{Kind: evidence.KindVulnerability, Observation: "unavailable"},
			},
			states: map[string]evidence.State{
				evidence.KindVulnerability: evidence.StateUnavailable,
			},
			wantVerdict: verdict.ApprovalRequired,
			wantRuleID:  "availability.no-cache",
			wantDegrade: true,
		},
		{
			name:    "unavailable evidence with fresh cache under balanced allows degraded",
			profile: Balanced,
			signals: []verdict.Signal{
				{Kind: evidence.KindVulnerability, Observation: "unavailable"},
				{Kind: evidence.KindCache, Observation: "fresh_allow"},
			},
			states: map[string]evidence.State{
				evidence.KindVulnerability: evidence.StateUnavailable,
			},
			wantVerdict: verdict.Allow,
			wantRuleID:  "availability.fresh-cache",
			wantDegrade: true,
		},
		{
			name:    "unavailable evidence without cache under strict blocks",
			profile: Strict,
			signals: []verdict.Signal{
				{Kind: evidence.KindVulnerability, Observation: "unavailable"},
			},
			states: map[string]evidence.State{
				evidence.KindVulnerability: evidence.StateUnavailable,
			},
			wantVerdict: verdict.Block,
			wantRuleID:  "availability.strict",
			wantDegrade: true,
		},
		{
			name:    "clean package satisfies policy and allows",
			profile: Balanced,
			signals: []verdict.Signal{
				{Kind: evidence.KindVulnerability, Observation: "none"},
				{Kind: evidence.KindIntegrity, Observation: "valid"},
			},
			wantVerdict: verdict.Allow,
			wantRuleID:  "core.policy-satisfied",
			wantDegrade: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			snap := evidence.NewSnapshot("test-pkg", "1.0.0", tt.signals, tt.states, baseTime)
			decision := EvaluateSnapshot(tt.profile, snap)

			if decision.Verdict != tt.wantVerdict {
				t.Fatalf("verdict = %q, want %q", decision.Verdict, tt.wantVerdict)
			}
			if decision.Degraded != tt.wantDegrade {
				t.Fatalf("degraded = %v, want %v", decision.Degraded, tt.wantDegrade)
			}
			if len(decision.Reasons) == 0 || decision.Reasons[0].RuleID != tt.wantRuleID {
				t.Fatalf("ruleID = %q, want %q", decision.Reasons[0].RuleID, tt.wantRuleID)
			}
		})
	}
}

func TestUnavailableEvidenceVisiblyUnavailableInDecision(t *testing.T) {
	baseTime := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	obs := []verdict.Signal{
		{
			Kind:        evidence.KindVulnerability,
			Source:      "npm-audit",
			Observation: "unavailable",
			Confidence:  evidence.ConfidenceNone,
			RetrievedAt: baseTime,
			FreshUntil:  baseTime,
		},
	}
	states := map[string]evidence.State{
		evidence.KindVulnerability: evidence.StateUnavailable,
	}

	snap := evidence.NewSnapshot("failing-pkg", "1.0.0", obs, states, baseTime)

	decision := EvaluateSnapshot(Balanced, snap)

	// Decision must explicitly indicate degradation
	if !decision.Degraded {
		t.Fatal("decision must be marked degraded when evidence is unavailable")
	}

	// Reason must visibly cite availability rule and availability signal
	if len(decision.Reasons) == 0 {
		t.Fatal("decision must include at least one reason")
	}

	reason := decision.Reasons[0]
	if reason.RuleID != "availability.no-cache" {
		t.Fatalf("expected rule 'availability.no-cache', got %q", reason.RuleID)
	}

	hasAvailabilitySignal := false
	for _, sigKind := range reason.SignalKinds {
		if sigKind == "availability" {
			hasAvailabilitySignal = true
			break
		}
	}
	if !hasAvailabilitySignal {
		t.Fatalf("reason signal kinds must include 'availability', got %v", reason.SignalKinds)
	}
}
