package policy

import (
	"testing"

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
