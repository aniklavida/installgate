package policy

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aniklavida/installgate/internal/evidence"
	"github.com/aniklavida/installgate/internal/verdict"
)

// The Eight Rows - Named Tests for Both Profiles

// Row 1: Integrity mismatch, or a known malicious package or version - block, block.
func TestRow1_IntegrityMismatchOrMalicious_Balanced_Blocks(t *testing.T) {
	cases := []struct {
		name       string
		assessment Assessment
	}{
		{"integrity mismatch", Assessment{IntegrityMismatch: true}},
		{"known malicious", Assessment{KnownMalicious: true}},
		{"both integrity and malicious", Assessment{IntegrityMismatch: true, KnownMalicious: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dec := Evaluate(Balanced, tc.assessment)
			if dec.Verdict != verdict.Block {
				t.Fatalf("verdict = %q, want %q", dec.Verdict, verdict.Block)
			}
			if len(dec.Reasons) == 0 || dec.Reasons[0].RuleID != "core.integrity-or-malicious" {
				t.Fatalf("expected rule core.integrity-or-malicious, got %+v", dec.Reasons)
			}
			if dec.Degraded {
				t.Fatal("degraded should be false for integrity/malicious block")
			}
		})
	}
}

func TestRow1_IntegrityMismatchOrMalicious_Strict_Blocks(t *testing.T) {
	cases := []struct {
		name       string
		assessment Assessment
	}{
		{"integrity mismatch", Assessment{IntegrityMismatch: true}},
		{"known malicious", Assessment{KnownMalicious: true}},
		{"both integrity and malicious", Assessment{IntegrityMismatch: true, KnownMalicious: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dec := Evaluate(Strict, tc.assessment)
			if dec.Verdict != verdict.Block {
				t.Fatalf("verdict = %q, want %q", dec.Verdict, verdict.Block)
			}
			if len(dec.Reasons) == 0 || dec.Reasons[0].RuleID != "core.integrity-or-malicious" {
				t.Fatalf("expected rule core.integrity-or-malicious, got %+v", dec.Reasons)
			}
			if dec.Degraded {
				t.Fatal("degraded should be false for integrity/malicious block")
			}
		})
	}
}

// Row 2: Vulnerability above the configured severity threshold - block, block.
func TestRow2_VulnerabilityAboveThreshold_Balanced_Blocks(t *testing.T) {
	dec := Evaluate(Balanced, Assessment{VulnerabilityAboveThreshold: true})
	if dec.Verdict != verdict.Block {
		t.Fatalf("verdict = %q, want %q", dec.Verdict, verdict.Block)
	}
	if len(dec.Reasons) == 0 || dec.Reasons[0].RuleID != "core.vulnerability-threshold" {
		t.Fatalf("expected rule core.vulnerability-threshold, got %+v", dec.Reasons)
	}
	if dec.Degraded {
		t.Fatal("degraded should be false")
	}
}

func TestRow2_VulnerabilityAboveThreshold_Strict_Blocks(t *testing.T) {
	dec := Evaluate(Strict, Assessment{VulnerabilityAboveThreshold: true})
	if dec.Verdict != verdict.Block {
		t.Fatalf("verdict = %q, want %q", dec.Verdict, verdict.Block)
	}
	if len(dec.Reasons) == 0 || dec.Reasons[0].RuleID != "core.vulnerability-threshold" {
		t.Fatalf("expected rule core.vulnerability-threshold, got %+v", dec.Reasons)
	}
	if dec.Degraded {
		t.Fatal("degraded should be false")
	}
}

// Row 3: Strong name confusion corroborated by a newborn or fresh package - approval required, block.
func TestRow3_StrongNameConfusionCorroboratedFresh_Balanced_RequiresApproval(t *testing.T) {
	dec := Evaluate(Balanced, Assessment{StrongNameConfusion: true, NewbornOrFresh: true, ConfusedWith: "react"})
	if dec.Verdict != verdict.ApprovalRequired {
		t.Fatalf("verdict = %q, want %q", dec.Verdict, verdict.ApprovalRequired)
	}
	if len(dec.Reasons) == 0 || dec.Reasons[0].RuleID != "identity.confusable-new" {
		t.Fatalf("expected rule identity.confusable-new, got %+v", dec.Reasons)
	}
	if !strings.Contains(dec.Reasons[0].Summary, "react") {
		t.Fatalf("summary should name confused-with target: %s", dec.Reasons[0].Summary)
	}
	if dec.Degraded {
		t.Fatal("degraded should be false")
	}
}

func TestRow3_StrongNameConfusionCorroboratedFresh_Strict_Blocks(t *testing.T) {
	dec := Evaluate(Strict, Assessment{StrongNameConfusion: true, NewbornOrFresh: true, ConfusedWith: "react"})
	if dec.Verdict != verdict.Block {
		t.Fatalf("verdict = %q, want %q", dec.Verdict, verdict.Block)
	}
	if len(dec.Reasons) == 0 || dec.Reasons[0].RuleID != "identity.confusable-new" {
		t.Fatalf("expected rule identity.confusable-new, got %+v", dec.Reasons)
	}
	if dec.Degraded {
		t.Fatal("degraded should be false")
	}
}

// Row 4: Publisher or provenance change combined with a newly introduced install script - approval required, block.
func TestRow4_PublisherProvenanceChangeWithInstallScript_Balanced_RequiresApproval(t *testing.T) {
	dec := Evaluate(Balanced, Assessment{PublisherOrProvenanceChanged: true, InstallScriptAdded: true})
	if dec.Verdict != verdict.ApprovalRequired {
		t.Fatalf("verdict = %q, want %q", dec.Verdict, verdict.ApprovalRequired)
	}
	if len(dec.Reasons) == 0 || dec.Reasons[0].RuleID != "release.provenance-script-change" {
		t.Fatalf("expected rule release.provenance-script-change, got %+v", dec.Reasons)
	}
	if dec.Degraded {
		t.Fatal("degraded should be false")
	}
}

func TestRow4_PublisherProvenanceChangeWithInstallScript_Strict_Blocks(t *testing.T) {
	dec := Evaluate(Strict, Assessment{PublisherOrProvenanceChanged: true, InstallScriptAdded: true})
	if dec.Verdict != verdict.Block {
		t.Fatalf("verdict = %q, want %q", dec.Verdict, verdict.Block)
	}
	if len(dec.Reasons) == 0 || dec.Reasons[0].RuleID != "release.provenance-script-change" {
		t.Fatalf("expected rule release.provenance-script-change, got %+v", dec.Reasons)
	}
	if dec.Degraded {
		t.Fatal("degraded should be false")
	}
}

// Row 5: Install script or implicit native build with no corroborating risk - warn and audit, approval required.
func TestRow5_InstallScriptUncorroborated_Balanced_Warns(t *testing.T) {
	dec := Evaluate(Balanced, Assessment{HasInstallScriptOrNativeBuild: true})
	if dec.Verdict != verdict.Warn {
		t.Fatalf("verdict = %q, want %q", dec.Verdict, verdict.Warn)
	}
	if len(dec.Reasons) == 0 || dec.Reasons[0].RuleID != "execution.install-time" {
		t.Fatalf("expected rule execution.install-time, got %+v", dec.Reasons)
	}
	if dec.Degraded {
		t.Fatal("degraded should be false")
	}
}

func TestRow5_InstallScriptUncorroborated_Strict_RequiresApproval(t *testing.T) {
	dec := Evaluate(Strict, Assessment{HasInstallScriptOrNativeBuild: true})
	if dec.Verdict != verdict.ApprovalRequired {
		t.Fatalf("verdict = %q, want %q", dec.Verdict, verdict.ApprovalRequired)
	}
	if len(dec.Reasons) == 0 || dec.Reasons[0].RuleID != "execution.install-time" {
		t.Fatalf("expected rule execution.install-time, got %+v", dec.Reasons)
	}
	if dec.Degraded {
		t.Fatal("degraded should be false")
	}
}

// Row 6: Evidence provider unavailable with a fresh cached allow - allow with a stale-evidence warning, approval required.
func TestRow6_EvidenceUnavailableFreshCachedAllow_Balanced_AllowsDegraded(t *testing.T) {
	dec := Evaluate(Balanced, Assessment{EvidenceUnavailable: true, FreshCachedAllow: true})
	if dec.Verdict != verdict.Allow {
		t.Fatalf("verdict = %q, want %q", dec.Verdict, verdict.Allow)
	}
	if len(dec.Reasons) == 0 || dec.Reasons[0].RuleID != "availability.fresh-cache" {
		t.Fatalf("expected rule availability.fresh-cache, got %+v", dec.Reasons)
	}
	if !dec.Degraded {
		t.Fatal("outage must explicitly set degraded = true")
	}
}

func TestRow6_EvidenceUnavailableFreshCachedAllow_Strict_RequiresApproval(t *testing.T) {
	dec := Evaluate(Strict, Assessment{EvidenceUnavailable: true, FreshCachedAllow: true})
	if dec.Verdict != verdict.ApprovalRequired {
		t.Fatalf("verdict = %q, want %q", dec.Verdict, verdict.ApprovalRequired)
	}
	if len(dec.Reasons) == 0 || dec.Reasons[0].RuleID != "availability.fresh-cache" {
		t.Fatalf("expected rule availability.fresh-cache, got %+v", dec.Reasons)
	}
	if !dec.Degraded {
		t.Fatal("outage must explicitly set degraded = true")
	}
}

// Row 7: Evidence provider unavailable with no usable cache - approval required, block.
func TestRow7_EvidenceUnavailableNoUsableCache_Balanced_RequiresApproval(t *testing.T) {
	dec := Evaluate(Balanced, Assessment{EvidenceUnavailable: true, FreshCachedAllow: false})
	if dec.Verdict != verdict.ApprovalRequired {
		t.Fatalf("verdict = %q, want %q", dec.Verdict, verdict.ApprovalRequired)
	}
	if len(dec.Reasons) == 0 || dec.Reasons[0].RuleID != "availability.no-cache" {
		t.Fatalf("expected rule availability.no-cache, got %+v", dec.Reasons)
	}
	if !dec.Degraded {
		t.Fatal("outage must explicitly set degraded = true")
	}
}

func TestRow7_EvidenceUnavailableNoUsableCache_Strict_Blocks(t *testing.T) {
	dec := Evaluate(Strict, Assessment{EvidenceUnavailable: true, FreshCachedAllow: false})
	if dec.Verdict != verdict.Block {
		t.Fatalf("verdict = %q, want %q", dec.Verdict, verdict.Block)
	}
	if len(dec.Reasons) == 0 || dec.Reasons[0].RuleID != "availability.strict" {
		t.Fatalf("expected rule availability.strict, got %+v", dec.Reasons)
	}
	if !dec.Degraded {
		t.Fatal("outage must explicitly set degraded = true")
	}
}

// Row 8: Low popularity or missing repository alone - informational, warn.
func TestRow8_LowPopularityOrMissingRepositoryAlone_Balanced_Informational(t *testing.T) {
	cases := []struct {
		name string
		a    Assessment
	}{
		{"low popularity", Assessment{LowPopularity: true}},
		{"missing repository", Assessment{MissingRepository: true}},
		{"both low popularity and missing repo", Assessment{LowPopularity: true, MissingRepository: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dec := Evaluate(Balanced, tc.a)
			if dec.Verdict != verdict.Allow {
				t.Fatalf("verdict = %q, want %q", dec.Verdict, verdict.Allow)
			}
			if len(dec.Reasons) == 0 || dec.Reasons[0].RuleID != "reputation.informational" {
				t.Fatalf("expected rule reputation.informational, got %+v", dec.Reasons)
			}
			if dec.Degraded {
				t.Fatal("degraded should be false")
			}
		})
	}
}

func TestRow8_LowPopularityOrMissingRepositoryAlone_Strict_Warns(t *testing.T) {
	cases := []struct {
		name string
		a    Assessment
	}{
		{"low popularity", Assessment{LowPopularity: true}},
		{"missing repository", Assessment{MissingRepository: true}},
		{"both low popularity and missing repo", Assessment{LowPopularity: true, MissingRepository: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dec := Evaluate(Strict, tc.a)
			if dec.Verdict != verdict.Warn {
				t.Fatalf("verdict = %q, want %q", dec.Verdict, verdict.Warn)
			}
			if len(dec.Reasons) == 0 || dec.Reasons[0].RuleID != "reputation.weak-signal" {
				t.Fatalf("expected rule reputation.weak-signal, got %+v", dec.Reasons)
			}
			if dec.Degraded {
				t.Fatal("degraded should be false")
			}
		})
	}
}

func TestDefault_CleanPackage_Balanced_Allows(t *testing.T) {
	dec := Evaluate(Balanced, Assessment{})
	if dec.Verdict != verdict.Allow {
		t.Fatalf("verdict = %q, want %q", dec.Verdict, verdict.Allow)
	}
	if len(dec.Reasons) == 0 || dec.Reasons[0].RuleID != "core.policy-satisfied" {
		t.Fatalf("expected rule core.policy-satisfied, got %+v", dec.Reasons)
	}
	if dec.Degraded {
		t.Fatal("degraded should be false")
	}
}

func TestDefault_CleanPackage_Strict_Allows(t *testing.T) {
	dec := Evaluate(Strict, Assessment{})
	if dec.Verdict != verdict.Allow {
		t.Fatalf("verdict = %q, want %q", dec.Verdict, verdict.Allow)
	}
	if len(dec.Reasons) == 0 || dec.Reasons[0].RuleID != "core.policy-satisfied" {
		t.Fatalf("expected rule core.policy-satisfied, got %+v", dec.Reasons)
	}
	if dec.Degraded {
		t.Fatal("degraded should be false")
	}
}

func TestEvaluateMatrix_AllSixteenPermutations(t *testing.T) {
	tests := []struct {
		name       string
		profile    Profile
		assessment Assessment
		want       verdict.Kind
		wantRuleID string
	}{
		{"row1 integrity balanced", Balanced, Assessment{IntegrityMismatch: true}, verdict.Block, "core.integrity-or-malicious"},
		{"row1 integrity strict", Strict, Assessment{IntegrityMismatch: true}, verdict.Block, "core.integrity-or-malicious"},
		{"row1 malicious balanced", Balanced, Assessment{KnownMalicious: true}, verdict.Block, "core.integrity-or-malicious"},
		{"row1 malicious strict", Strict, Assessment{KnownMalicious: true}, verdict.Block, "core.integrity-or-malicious"},
		{"row2 vuln balanced", Balanced, Assessment{VulnerabilityAboveThreshold: true}, verdict.Block, "core.vulnerability-threshold"},
		{"row2 vuln strict", Strict, Assessment{VulnerabilityAboveThreshold: true}, verdict.Block, "core.vulnerability-threshold"},
		{"row3 confusable fresh balanced", Balanced, Assessment{StrongNameConfusion: true, NewbornOrFresh: true}, verdict.ApprovalRequired, "identity.confusable-new"},
		{"row3 confusable fresh strict", Strict, Assessment{StrongNameConfusion: true, NewbornOrFresh: true}, verdict.Block, "identity.confusable-new"},
		{"row4 provenance script balanced", Balanced, Assessment{PublisherOrProvenanceChanged: true, InstallScriptAdded: true}, verdict.ApprovalRequired, "release.provenance-script-change"},
		{"row4 provenance script strict", Strict, Assessment{PublisherOrProvenanceChanged: true, InstallScriptAdded: true}, verdict.Block, "release.provenance-script-change"},
		{"row5 install script balanced", Balanced, Assessment{HasInstallScriptOrNativeBuild: true}, verdict.Warn, "execution.install-time"},
		{"row5 install script strict", Strict, Assessment{HasInstallScriptOrNativeBuild: true}, verdict.ApprovalRequired, "execution.install-time"},
		{"row6 outage cached balanced", Balanced, Assessment{EvidenceUnavailable: true, FreshCachedAllow: true}, verdict.Allow, "availability.fresh-cache"},
		{"row6 outage cached strict", Strict, Assessment{EvidenceUnavailable: true, FreshCachedAllow: true}, verdict.ApprovalRequired, "availability.fresh-cache"},
		{"row7 outage no cache balanced", Balanced, Assessment{EvidenceUnavailable: true}, verdict.ApprovalRequired, "availability.no-cache"},
		{"row7 outage no cache strict", Strict, Assessment{EvidenceUnavailable: true}, verdict.Block, "availability.strict"},
		{"row8 low popularity balanced", Balanced, Assessment{LowPopularity: true}, verdict.Allow, "reputation.informational"},
		{"row8 low popularity strict", Strict, Assessment{LowPopularity: true}, verdict.Warn, "reputation.weak-signal"},
		{"row8 missing repo balanced", Balanced, Assessment{MissingRepository: true}, verdict.Allow, "reputation.informational"},
		{"row8 missing repo strict", Strict, Assessment{MissingRepository: true}, verdict.Warn, "reputation.weak-signal"},
		{"clean balanced", Balanced, Assessment{}, verdict.Allow, "core.policy-satisfied"},
		{"clean strict", Strict, Assessment{}, verdict.Allow, "core.policy-satisfied"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Evaluate(tt.profile, tt.assessment)
			if got.Verdict != tt.want {
				t.Fatalf("verdict = %q, want %q", got.Verdict, tt.want)
			}
			if len(got.Reasons) == 0 || got.Reasons[0].RuleID != tt.wantRuleID {
				t.Fatalf("ruleID = %q, want %q", got.Reasons[0].RuleID, tt.wantRuleID)
			}
		})
	}
}

// Property Test: Across the whole assessment input space (all 2^13 combinations),
// Strict is NEVER more permissive than Balanced.
func TestPropertyStrictNeverMorePermissiveThanBalanced(t *testing.T) {
	rank := func(k verdict.Kind) int {
		switch k {
		case verdict.Block:
			return 0
		case verdict.ApprovalRequired:
			return 1
		case verdict.Warn:
			return 2
		case verdict.Allow:
			return 3
		default:
			t.Fatalf("unknown verdict kind: %s", k)
			return -1
		}
	}

	totalCombinations := 1 << 13 // 8192 combinations
	for mask := 0; mask < totalCombinations; mask++ {
		a := Assessment{
			IntegrityMismatch:             (mask & (1 << 0)) != 0,
			KnownMalicious:                (mask & (1 << 1)) != 0,
			VulnerabilityAboveThreshold:   (mask & (1 << 2)) != 0,
			StrongNameConfusion:           (mask & (1 << 3)) != 0,
			NewbornOrFresh:                (mask & (1 << 4)) != 0,
			PublisherOrProvenanceChanged:  (mask & (1 << 5)) != 0,
			InstallScriptAdded:            (mask & (1 << 6)) != 0,
			HasInstallScriptOrNativeBuild: (mask & (1 << 7)) != 0,
			EvidenceUnavailable:           (mask & (1 << 8)) != 0,
			FreshCachedAllow:              (mask & (1 << 9)) != 0,
			LowPopularity:                 (mask & (1 << 10)) != 0,
			MissingRepository:             (mask & (1 << 11)) != 0,
			PackageNotFound:               (mask & (1 << 12)) != 0,
		}

		bal := Evaluate(Balanced, a)
		str := Evaluate(Strict, a)

		balRank := rank(bal.Verdict)
		strRank := rank(str.Verdict)

		if strRank > balRank {
			t.Fatalf("PROPERTY VIOLATION at mask %013b:\nStrict (%q, rank %d) is more permissive than Balanced (%q, rank %d)\nAssessment: %+v",
				mask, str.Verdict, strRank, bal.Verdict, balRank, a)
		}
	}
}

// Hard Constraint Test: A positive result is 'allowed by this policy with this evidence', NEVER 'safe'.
// The word "safe" must not appear in any allow reason across the entire input space.
func TestNoAllowReasonClaimsSafety(t *testing.T) {
	profiles := []Profile{Balanced, Strict}

	totalCombinations := 1 << 13
	for mask := 0; mask < totalCombinations; mask++ {
		a := Assessment{
			IntegrityMismatch:             (mask & (1 << 0)) != 0,
			KnownMalicious:                (mask & (1 << 1)) != 0,
			VulnerabilityAboveThreshold:   (mask & (1 << 2)) != 0,
			StrongNameConfusion:           (mask & (1 << 3)) != 0,
			NewbornOrFresh:                (mask & (1 << 4)) != 0,
			PublisherOrProvenanceChanged:  (mask & (1 << 5)) != 0,
			InstallScriptAdded:            (mask & (1 << 6)) != 0,
			HasInstallScriptOrNativeBuild: (mask & (1 << 7)) != 0,
			EvidenceUnavailable:           (mask & (1 << 8)) != 0,
			FreshCachedAllow:              (mask & (1 << 9)) != 0,
			LowPopularity:                 (mask & (1 << 10)) != 0,
			MissingRepository:             (mask & (1 << 11)) != 0,
			PackageNotFound:               (mask & (1 << 12)) != 0,
		}

		for _, prof := range profiles {
			dec := Evaluate(prof, a)
			if dec.Verdict == verdict.Allow {
				for _, r := range dec.Reasons {
					summaryLower := strings.ToLower(r.Summary)
					ruleLower := strings.ToLower(r.RuleID)
					if strings.Contains(summaryLower, "safe") {
						t.Fatalf("allow reason summary must NEVER claim safety: found in %q (rule %s, profile %s)", r.Summary, r.RuleID, prof)
					}
					if strings.Contains(ruleLower, "safe") {
						t.Fatalf("allow rule ID must NEVER claim safety: found in %q", r.RuleID)
					}
				}
			}
		}
	}
}

// Hard Constraint Test: Low popularity or a missing repository can NEVER independently produce approval_required or block.
func TestLowPopularityOrMissingRepositoryNeverBlocksOrRequiresApproval(t *testing.T) {
	profiles := []Profile{Balanced, Strict}
	cases := []struct {
		name string
		a    Assessment
	}{
		{"low popularity only", Assessment{LowPopularity: true}},
		{"missing repository only", Assessment{MissingRepository: true}},
		{"both low popularity and missing repository", Assessment{LowPopularity: true, MissingRepository: true}},
	}

	for _, tc := range cases {
		for _, prof := range profiles {
			t.Run(fmt.Sprintf("%s/%s", tc.name, prof), func(t *testing.T) {
				dec := Evaluate(prof, tc.a)
				if dec.Verdict == verdict.Block || dec.Verdict == verdict.ApprovalRequired {
					t.Fatalf("low popularity/missing repo must NEVER independently produce %q: got %q (profile %s)",
						dec.Verdict, dec.Verdict, prof)
				}
			})
		}
	}
}

// Corroboration Logic Test: Heuristic signals reach approval or block ONLY when corroborated by a second independent signal.
func TestCorroborationLogic_HeuristicSignalRequiresSecondIndependentSignal(t *testing.T) {
	profiles := []Profile{Balanced, Strict}

	// Uncorroborated name confusion: no fresh signal -> must NOT reach approval_required or block
	for _, prof := range profiles {
		dec := Evaluate(prof, Assessment{StrongNameConfusion: true, NewbornOrFresh: false})
		if dec.Verdict == verdict.Block || dec.Verdict == verdict.ApprovalRequired {
			t.Fatalf("uncorroborated strong name confusion must not reach approval_required or block: got %q (profile %s)", dec.Verdict, prof)
		}
		if dec.Verdict != verdict.Allow {
			t.Fatalf("uncorroborated strong name confusion on mature package should allow, got %q", dec.Verdict)
		}
	}

	// Uncorroborated newborn/fresh: no name confusion -> must NOT reach approval_required or block
	for _, prof := range profiles {
		dec := Evaluate(prof, Assessment{NewbornOrFresh: true})
		if dec.Verdict == verdict.Block || dec.Verdict == verdict.ApprovalRequired {
			t.Fatalf("uncorroborated newborn/fresh must not reach approval_required or block: got %q (profile %s)", dec.Verdict, prof)
		}
		if dec.Verdict != verdict.Allow {
			t.Fatalf("uncorroborated newborn/fresh should allow, got %q", dec.Verdict)
		}
	}

	// Uncorroborated provenance change: no script added -> must NOT reach approval_required or block
	for _, prof := range profiles {
		dec := Evaluate(prof, Assessment{PublisherOrProvenanceChanged: true, InstallScriptAdded: false})
		if dec.Verdict == verdict.Block || dec.Verdict == verdict.ApprovalRequired {
			t.Fatalf("uncorroborated publisher/provenance change must not reach approval_required or block: got %q (profile %s)", dec.Verdict, prof)
		}
		if dec.Verdict != verdict.Allow {
			t.Fatalf("uncorroborated publisher/provenance change should allow, got %q", dec.Verdict)
		}
	}

	// Corroborated: name confusion + fresh -> reaches approval_required (balanced) and block (strict)
	decConfCorrobBal := Evaluate(Balanced, Assessment{StrongNameConfusion: true, NewbornOrFresh: true})
	if decConfCorrobBal.Verdict != verdict.ApprovalRequired {
		t.Fatalf("corroborated name confusion under balanced must require approval, got %q", decConfCorrobBal.Verdict)
	}
	decConfCorrobStr := Evaluate(Strict, Assessment{StrongNameConfusion: true, NewbornOrFresh: true})
	if decConfCorrobStr.Verdict != verdict.Block {
		t.Fatalf("corroborated name confusion under strict must block, got %q", decConfCorrobStr.Verdict)
	}

	// Corroborated: provenance change + install script added -> reaches approval_required (balanced) and block (strict)
	decProvCorrobBal := Evaluate(Balanced, Assessment{PublisherOrProvenanceChanged: true, InstallScriptAdded: true})
	if decProvCorrobBal.Verdict != verdict.ApprovalRequired {
		t.Fatalf("corroborated provenance change under balanced must require approval, got %q", decProvCorrobBal.Verdict)
	}
	decProvCorrobStr := Evaluate(Strict, Assessment{PublisherOrProvenanceChanged: true, InstallScriptAdded: true})
	if decProvCorrobStr.Verdict != verdict.Block {
		t.Fatalf("corroborated provenance change under strict must block, got %q", decProvCorrobStr.Verdict)
	}
}

// Hard Constraint Test: First-seen and changed-risk packages take a stricter path than an unchanged, previously allowed package.
func TestFirstSeenAndChangedRiskStricterThanUnchangedPreviouslyAllowed(t *testing.T) {
	rank := func(k verdict.Kind) int {
		switch k {
		case verdict.Block:
			return 0
		case verdict.ApprovalRequired:
			return 1
		case verdict.Warn:
			return 2
		case verdict.Allow:
			return 3
		default:
			panic(k)
		}
	}

	// During an evidence outage:
	// Unchanged, previously allowed package has fresh cached allow
	unchangedBalanced := Evaluate(Balanced, Assessment{EvidenceUnavailable: true, FreshCachedAllow: true})
	unchangedStrict := Evaluate(Strict, Assessment{EvidenceUnavailable: true, FreshCachedAllow: true})

	// First-seen package has no cached allow
	firstSeenBalanced := Evaluate(Balanced, Assessment{EvidenceUnavailable: true, FreshCachedAllow: false})
	firstSeenStrict := Evaluate(Strict, Assessment{EvidenceUnavailable: true, FreshCachedAllow: false})

	// Assert first-seen is strictly more restrictive (lower rank) than unchanged
	if rank(firstSeenBalanced.Verdict) >= rank(unchangedBalanced.Verdict) {
		t.Fatalf("first-seen balanced (%q) must be stricter than unchanged (%q)", firstSeenBalanced.Verdict, unchangedBalanced.Verdict)
	}
	if rank(firstSeenStrict.Verdict) >= rank(unchangedStrict.Verdict) {
		t.Fatalf("first-seen strict (%q) must be stricter than unchanged (%q)", firstSeenStrict.Verdict, unchangedStrict.Verdict)
	}

	// Changed-risk package (e.g. newly introduced install script with publisher change)
	changedRiskBalanced := Evaluate(Balanced, Assessment{PublisherOrProvenanceChanged: true, InstallScriptAdded: true, FreshCachedAllow: true})
	changedRiskStrict := Evaluate(Strict, Assessment{PublisherOrProvenanceChanged: true, InstallScriptAdded: true, FreshCachedAllow: true})

	if rank(changedRiskBalanced.Verdict) >= rank(unchangedBalanced.Verdict) {
		t.Fatalf("changed-risk balanced (%q) must be stricter than unchanged (%q)", changedRiskBalanced.Verdict, unchangedBalanced.Verdict)
	}
	if rank(changedRiskStrict.Verdict) >= rank(unchangedStrict.Verdict) {
		t.Fatalf("changed-risk strict (%q) must be stricter than unchanged (%q)", changedRiskStrict.Verdict, unchangedStrict.Verdict)
	}
}

// Hard Constraint Test: An evidence outage never silently becomes a clean result;
// the degraded flag must be set on every availability row.
func TestOutageDegradedFlagAlwaysSetOnAvailabilityRows(t *testing.T) {
	// Row 6: fresh cache
	dec6Bal := Evaluate(Balanced, Assessment{EvidenceUnavailable: true, FreshCachedAllow: true})
	if !dec6Bal.Degraded {
		t.Fatal("row 6 balanced must have degraded = true")
	}
	dec6Str := Evaluate(Strict, Assessment{EvidenceUnavailable: true, FreshCachedAllow: true})
	if !dec6Str.Degraded {
		t.Fatal("row 6 strict must have degraded = true")
	}

	// Row 7: no cache
	dec7Bal := Evaluate(Balanced, Assessment{EvidenceUnavailable: true, FreshCachedAllow: false})
	if !dec7Bal.Degraded {
		t.Fatal("row 7 balanced must have degraded = true")
	}
	dec7Str := Evaluate(Strict, Assessment{EvidenceUnavailable: true, FreshCachedAllow: false})
	if !dec7Str.Degraded {
		t.Fatal("row 7 strict must have degraded = true")
	}
}

// Determinism Test: Replaying identical policy, input, and snapshot must produce identical output.
func TestDeterminismAcrossMatrix(t *testing.T) {
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

	for _, prof := range []Profile{Balanced, Strict} {
		initial := EvaluateSnapshot(prof, snap)
		for i := 0; i < 20; i++ {
			replayed := EvaluateSnapshot(prof, snap)
			if !reflect.DeepEqual(initial, replayed) {
				t.Fatalf("iteration %d produced divergent decision: got %+v, want %+v", i, replayed, initial)
			}
		}
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

	if !decision.Degraded {
		t.Fatal("decision must be marked degraded when evidence is unavailable")
	}

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
