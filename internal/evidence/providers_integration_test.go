package evidence_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aniklavida/installgate/internal/evidence"
	"github.com/aniklavida/installgate/internal/policy"
	"github.com/aniklavida/installgate/internal/verdict"
)

type packumentTimeDoc struct {
	Name     string                 `json:"name"`
	Time     map[string]string      `json:"time"`
	Versions map[string]interface{} `json:"versions"`
}

type osvAffected struct {
	Package  osvPackageRef `json:"package"`
	Ranges   []osvRange    `json:"ranges"`
	Versions []string      `json:"versions"`
}

type osvPackageRef struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

type osvVulnerability struct {
	ID               string                 `json:"id"`
	Summary          string                 `json:"summary"`
	DatabaseSpecific map[string]interface{} `json:"database_specific,omitempty"`
	Affected         []osvAffected          `json:"affected,omitempty"`
}

type osvQueryResponse struct {
	Vulns []osvVulnerability `json:"vulns"`
}

func TestSyntheticNewbornConfusablePackageEndToEnd(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	created := now.Add(-2 * time.Hour) // newborn (2 hours old)

	// Registry server: returns packument for newborn package "reqeust"
	regServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(packumentTimeDoc{
			Name: "reqeust",
			Time: map[string]string{
				"created": created.Format(time.RFC3339Nano),
				"1.0.0":   created.Format(time.RFC3339Nano),
			},
			Versions: map[string]interface{}{
				"1.0.0": map[string]interface{}{},
			},
		})
	}))
	defer regServer.Close()

	// OSV server: returns empty vulns for "reqeust"
	osvServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(osvQueryResponse{
			Vulns: []osvVulnerability{},
		})
	}))
	defer osvServer.Close()

	clock := func() time.Time { return now }

	advisoryProv := evidence.NewAdvisoryProvider(
		evidence.WithAdvisoryBaseURL(osvServer.URL),
		evidence.WithAdvisoryClock(clock),
	)
	historyProv := evidence.NewHistoryProvider(
		evidence.WithHistoryRegistryURL(regServer.URL),
		evidence.WithHistoryClock(clock),
	)
	provenanceProv := evidence.NewProvenanceProvider(
		evidence.WithProvenanceRegistryURL(regServer.URL),
		evidence.WithProvenanceClock(clock),
	)
	corpus := evidence.SliceCorpus{"request", "react", "express", "lodash"}
	confusionProv := evidence.NewConfusionProvider(
		evidence.WithConfusionCorpus(corpus),
		evidence.WithConfusionClock(clock),
	)

	assembler := evidence.NewAssembler(
		evidence.WithClock(clock),
		evidence.WithProviders(advisoryProv, historyProv, provenanceProv, confusionProv),
	)

	snap, err := assembler.Assemble(context.Background(), "reqeust", "1.0.0")
	if err != nil {
		t.Fatalf("assemble failed: %v", err)
	}

	// 1. Evaluate under Balanced profile -> must be approval_required
	decBalanced := policy.EvaluateSnapshot(policy.Balanced, snap)
	if decBalanced.Verdict != verdict.ApprovalRequired {
		t.Fatalf("balanced profile verdict = %q, want %q", decBalanced.Verdict, verdict.ApprovalRequired)
	}
	if len(decBalanced.Reasons) == 0 {
		t.Fatal("expected at least one reason in decision")
	}
	reasonBalanced := decBalanced.Reasons[0]
	if reasonBalanced.RuleID != "identity.confusable-new" {
		t.Fatalf("ruleID = %q, want 'identity.confusable-new'", reasonBalanced.RuleID)
	}
	// Hard constraint: The reason names the specific target it was confused with
	if !strings.Contains(reasonBalanced.Summary, "request") {
		t.Fatalf("expected reason summary to name target 'request', got %q", reasonBalanced.Summary)
	}

	// 2. Evaluate under Strict profile -> must be block
	decStrict := policy.EvaluateSnapshot(policy.Strict, snap)
	if decStrict.Verdict != verdict.Block {
		t.Fatalf("strict profile verdict = %q, want %q", decStrict.Verdict, verdict.Block)
	}
	if len(decStrict.Reasons) == 0 {
		t.Fatal("expected at least one reason in strict decision")
	}
	reasonStrict := decStrict.Reasons[0]
	if reasonStrict.RuleID != "identity.confusable-new" {
		t.Fatalf("strict ruleID = %q, want 'identity.confusable-new'", reasonStrict.RuleID)
	}
	// Hard constraint: The reason names the specific target it was confused with
	if !strings.Contains(reasonStrict.Summary, "request") {
		t.Fatalf("expected strict reason summary to name target 'request', got %q", reasonStrict.Summary)
	}
}

func TestConfusableMatchWithoutFreshnessDoesNotConvict(t *testing.T) {
	// A mature package that is similar in name to a popular package must NOT be blocked
	// or held solely on a bare similarity score.
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	created := now.Add(-500 * 24 * time.Hour) // established 500 days ago
	vPub := now.Add(-100 * 24 * time.Hour)    // published 100 days ago

	regServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(packumentTimeDoc{
			Name: "reqeust",
			Time: map[string]string{
				"created": created.Format(time.RFC3339Nano),
				"1.0.0":   vPub.Format(time.RFC3339Nano),
			},
			Versions: map[string]interface{}{
				"1.0.0": map[string]interface{}{},
			},
		})
	}))
	defer regServer.Close()

	osvServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(osvQueryResponse{
			Vulns: []osvVulnerability{},
		})
	}))
	defer osvServer.Close()

	clock := func() time.Time { return now }

	advisoryProv := evidence.NewAdvisoryProvider(evidence.WithAdvisoryBaseURL(osvServer.URL), evidence.WithAdvisoryClock(clock))
	historyProv := evidence.NewHistoryProvider(evidence.WithHistoryRegistryURL(regServer.URL), evidence.WithHistoryClock(clock))
	provenanceProv := evidence.NewProvenanceProvider(evidence.WithProvenanceRegistryURL(regServer.URL), evidence.WithProvenanceClock(clock))
	corpus := evidence.SliceCorpus{"request"}
	confusionProv := evidence.NewConfusionProvider(evidence.WithConfusionCorpus(corpus), evidence.WithConfusionClock(clock))

	assembler := evidence.NewAssembler(
		evidence.WithClock(clock),
		evidence.WithProviders(advisoryProv, historyProv, provenanceProv, confusionProv),
	)

	snap, err := assembler.Assemble(context.Background(), "reqeust", "1.0.0")
	if err != nil {
		t.Fatalf("assemble failed: %v", err)
	}

	decBalanced := policy.EvaluateSnapshot(policy.Balanced, snap)
	// Without freshness corroboration, bare similarity does not trigger identity.confusable-new hold
	if decBalanced.Verdict != verdict.Allow {
		t.Fatalf("expected mature confusable package to allow in balanced mode, got %q (reasons: %+v)", decBalanced.Verdict, decBalanced.Reasons)
	}
}

func TestNonexistentPackageNeverMaliciousEndToEnd(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)

	// Registry returns 404
	regServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"Not found"}`, http.StatusNotFound)
	}))
	defer regServer.Close()

	// OSV returns empty results
	osvServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(osvQueryResponse{
			Vulns: []osvVulnerability{},
		})
	}))
	defer osvServer.Close()

	clock := func() time.Time { return now }

	advisoryProv := evidence.NewAdvisoryProvider(evidence.WithAdvisoryBaseURL(osvServer.URL), evidence.WithAdvisoryClock(clock))
	historyProv := evidence.NewHistoryProvider(evidence.WithHistoryRegistryURL(regServer.URL), evidence.WithHistoryClock(clock))
	provenanceProv := evidence.NewProvenanceProvider(evidence.WithProvenanceRegistryURL(regServer.URL), evidence.WithProvenanceClock(clock))
	corpus := evidence.SliceCorpus{"react", "express"}
	confusionProv := evidence.NewConfusionProvider(evidence.WithConfusionCorpus(corpus), evidence.WithConfusionClock(clock))

	assembler := evidence.NewAssembler(
		evidence.WithClock(clock),
		evidence.WithProviders(advisoryProv, historyProv, provenanceProv, confusionProv),
	)

	snap, err := assembler.Assemble(context.Background(), "hallucinated-fake-lib-xyz", "1.0.0")
	if err != nil {
		t.Fatalf("assemble failed: %v", err)
	}

	for _, prof := range []policy.Profile{policy.Balanced, policy.Strict} {
		dec := policy.EvaluateSnapshot(prof, snap)

		// Hard constraint: A nonexistent package fails as nonexistent and is NEVER labelled malicious.
		// A nonexistent package produces a clear not-found result containing no malicious language, asserted by test.
		if dec.Verdict != verdict.Block {
			t.Fatalf("[%s] expected verdict Block for nonexistent package, got %q", prof, dec.Verdict)
		}
		if len(dec.Reasons) == 0 {
			t.Fatalf("[%s] expected at least one reason", prof)
		}

		for _, r := range dec.Reasons {
			if r.RuleID == "core.integrity-or-malicious" {
				t.Fatalf("[%s] nonexistent package must NEVER trigger malicious rule, got ruleID %q", prof, r.RuleID)
			}
			rSummaryLower := strings.ToLower(r.Summary)
			if strings.Contains(rSummaryLower, "malicious") || strings.Contains(rSummaryLower, "malware") {
				t.Fatalf("[%s] nonexistent package reason contains forbidden malicious language: %q", prof, r.Summary)
			}
			for _, sigKind := range r.SignalKinds {
				if sigKind == "malicious" {
					t.Fatalf("[%s] nonexistent package reason contains forbidden 'malicious' signal kind", prof)
				}
			}
		}

		if dec.Reasons[0].RuleID != "registry.package-not-found" {
			t.Fatalf("[%s] expected ruleID 'registry.package-not-found', got %q", prof, dec.Reasons[0].RuleID)
		}
	}
}

func TestEmptyBodyUnableToProduceCleanAllowAnywhere(t *testing.T) {
	// Hard constraint: A provider returning an empty body is proven unable to produce a clean allow anywhere in the system.
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	// Test each provider individually returning 0 bytes
	t.Run("advisory provider empty body", func(t *testing.T) {
		emptyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK) // 0-byte body
		}))
		defer emptyServer.Close()

		p := evidence.NewAdvisoryProvider(evidence.WithAdvisoryBaseURL(emptyServer.URL), evidence.WithAdvisoryClock(clock))
		assembler := evidence.NewAssembler(evidence.WithClock(clock), evidence.WithProviders(p))
		snap, err := assembler.Assemble(context.Background(), "pkg", "1.0.0")
		if err != nil {
			t.Fatalf("assemble failed: %v", err)
		}

		for _, prof := range []policy.Profile{policy.Balanced, policy.Strict} {
			dec := policy.EvaluateSnapshot(prof, snap)
			// A clean allow is verdict.Allow with Degraded == false
			if dec.Verdict == verdict.Allow && !dec.Degraded {
				t.Fatalf("[%s] empty body produced clean allow!", prof)
			}
		}
	})

	t.Run("history provider empty body", func(t *testing.T) {
		emptyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK) // 0-byte body
		}))
		defer emptyServer.Close()

		p := evidence.NewHistoryProvider(evidence.WithHistoryRegistryURL(emptyServer.URL), evidence.WithHistoryClock(clock))
		assembler := evidence.NewAssembler(evidence.WithClock(clock), evidence.WithProviders(p))
		snap, err := assembler.Assemble(context.Background(), "pkg", "1.0.0")
		if err != nil {
			t.Fatalf("assemble failed: %v", err)
		}

		for _, prof := range []policy.Profile{policy.Balanced, policy.Strict} {
			dec := policy.EvaluateSnapshot(prof, snap)
			if dec.Verdict == verdict.Allow && !dec.Degraded {
				t.Fatalf("[%s] empty body produced clean allow!", prof)
			}
		}
	})

	t.Run("provenance provider empty body", func(t *testing.T) {
		emptyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK) // 0-byte body
		}))
		defer emptyServer.Close()

		p := evidence.NewProvenanceProvider(evidence.WithProvenanceRegistryURL(emptyServer.URL), evidence.WithProvenanceClock(clock))
		assembler := evidence.NewAssembler(evidence.WithClock(clock), evidence.WithProviders(p))
		snap, err := assembler.Assemble(context.Background(), "pkg", "1.0.0")
		if err != nil {
			t.Fatalf("assemble failed: %v", err)
		}

		for _, prof := range []policy.Profile{policy.Balanced, policy.Strict} {
			dec := policy.EvaluateSnapshot(prof, snap)
			if dec.Verdict == verdict.Allow && !dec.Degraded {
				t.Fatalf("[%s] empty body produced clean allow!", prof)
			}
		}
	})

	t.Run("confusion provider empty corpus", func(t *testing.T) {
		p := evidence.NewConfusionProvider(evidence.WithConfusionCorpus(evidence.SliceCorpus{}), evidence.WithConfusionClock(clock))
		assembler := evidence.NewAssembler(evidence.WithClock(clock), evidence.WithProviders(p))
		snap, err := assembler.Assemble(context.Background(), "pkg", "1.0.0")
		if err != nil {
			t.Fatalf("assemble failed: %v", err)
		}

		for _, prof := range []policy.Profile{policy.Balanced, policy.Strict} {
			dec := policy.EvaluateSnapshot(prof, snap)
			if dec.Verdict == verdict.Allow && !dec.Degraded {
				t.Fatalf("[%s] empty corpus produced clean allow!", prof)
			}
		}
	})
}
