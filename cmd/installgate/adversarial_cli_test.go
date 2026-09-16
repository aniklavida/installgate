package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aniklavida/installgate/internal/evidence"
	"github.com/aniklavida/installgate/internal/explanation"
	"github.com/aniklavida/installgate/internal/gateway"
	"github.com/aniklavida/installgate/internal/policy"
	"github.com/aniklavida/installgate/internal/store"
	"github.com/aniklavida/installgate/internal/verdict"
)

// TestEmptyAdvisoryResponseCannotProduceCleanAllow_CLI proves that an advisory provider returning
// HTTP 200 with [] can NEVER produce a clean allow at the CLI surface (installgate check),
// and that the degraded flag survives into both human and JSON renderings.
func TestEmptyAdvisoryResponseCannotProduceCleanAllow_CLI(t *testing.T) {
	now := time.Date(2026, 9, 15, 14, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	// 1. Mock registry
	regServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"name": "cli-empty-adv-pkg",
			"time": map[string]string{
				"created": now.Add(-60 * 24 * time.Hour).Format(time.RFC3339),
				"1.0.0":   now.Add(-60 * 24 * time.Hour).Format(time.RFC3339),
			},
			"versions": map[string]interface{}{
				"1.0.0": map[string]interface{}{},
			},
		})
	}))
	defer regServer.Close()

	// 2. Mock advisory provider returning 200 OK with []
	advisoryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("[]"))
	}))
	defer advisoryServer.Close()

	scenarios := []struct {
		name            string
		profile         policy.Profile
		withFreshCache  bool
		expectedVerdict verdict.Kind
		expectedRuleID  string
	}{
		{
			name:            "CLI_NoCache_Balanced_ApprovalRequired",
			profile:         policy.Balanced,
			withFreshCache:  false,
			expectedVerdict: verdict.ApprovalRequired,
			expectedRuleID:  "availability.no-cache",
		},
		{
			name:            "CLI_NoCache_Strict_Blocked",
			profile:         policy.Strict,
			withFreshCache:  false,
			expectedVerdict: verdict.Block,
			expectedRuleID:  "availability.strict",
		},
		{
			name:            "CLI_FreshCache_Balanced_DegradedAllowWithWarning",
			profile:         policy.Balanced,
			withFreshCache:  true,
			expectedVerdict: verdict.Allow,
			expectedRuleID:  "availability.fresh-cache",
		},
		{
			name:            "CLI_FreshCache_Strict_ApprovalRequired",
			profile:         policy.Strict,
			withFreshCache:  true,
			expectedVerdict: verdict.ApprovalRequired,
			expectedRuleID:  "availability.fresh-cache",
		},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			tempDir := t.TempDir()
			dbPath := filepath.Join(tempDir, "cli_test.db")
			dbStore, err := store.OpenSQLite(dbPath)
			if err != nil {
				t.Fatalf("OpenSQLite failed: %v", err)
			}
			defer dbStore.Close()
			if err := dbStore.ApplyMigrations(context.Background()); err != nil {
				t.Fatalf("ApplyMigrations failed: %v", err)
			}

			cache := evidence.NewMemoryCache()
			if sc.withFreshCache {
				cache.PutCachedAllow(
					"cli-empty-adv-pkg",
					"1.0.0",
					verdict.Decision{
						Verdict: verdict.Allow,
						Reasons: []verdict.Reason{{RuleID: "core.policy-satisfied"}},
					},
					"sha256:dummy",
					now.Add(-1*time.Hour),
					now.Add(23*time.Hour),
					now.Add(48*time.Hour),
				)
			}

			advisoryProv := evidence.NewAdvisoryProvider(
				evidence.WithAdvisoryBaseURL(advisoryServer.URL),
				evidence.WithAdvisoryClock(clock),
			)
			historyProv := evidence.NewHistoryProvider(
				evidence.WithHistoryRegistryURL(regServer.URL),
				evidence.WithHistoryClock(clock),
			)

			assembler := evidence.NewAssembler(
				evidence.WithClock(clock),
				evidence.WithCache(cache),
				evidence.WithFreshnessPolicy(evidence.DefaultFreshnessPolicy()),
				evidence.WithProviders(advisoryProv, historyProv),
			)

			pol := &policy.Policy{
				Version:                policy.CurrentPolicyVersion,
				Profile:                sc.profile,
				VulnerabilityThreshold: policy.SeverityHigh,
			}

			engine := gateway.NewEngine(gateway.EngineConfig{
				Policy:    pol,
				Assembler: assembler,
				Store:     dbStore,
				Actor:     "cli",
			})

			ctx := context.Background()
			doc, err := engine.Evaluate(ctx, "cli-empty-adv-pkg", "1.0.0")
			if err != nil {
				t.Fatalf("engine.Evaluate failed: %v", err)
			}

			// PROVE: Never a clean allow!
			if doc.Verdict == verdict.Allow && !doc.Degraded {
				t.Fatalf("SECURITY FAILURE: CLI check produced clean allow from empty advisory response! doc: %+v", doc)
			}

			if doc.Verdict != sc.expectedVerdict {
				t.Fatalf("expected verdict %q, got %q", sc.expectedVerdict, doc.Verdict)
			}

			if len(doc.Reasons) == 0 || doc.Reasons[0].RuleID != sc.expectedRuleID {
				t.Fatalf("expected rule ID %q, got: %+v", sc.expectedRuleID, doc.Reasons)
			}

			if !doc.Degraded {
				t.Fatal("expected doc.Degraded = true")
			}

			// Verify JSON rendering preserves degraded
			jsonBytes, err := explanation.RenderJSON(doc)
			if err != nil {
				t.Fatalf("RenderJSON failed: %v", err)
			}
			var parsedJSON map[string]interface{}
			if err := json.Unmarshal(jsonBytes, &parsedJSON); err != nil {
				t.Fatalf("unmarshal JSON failed: %v", err)
			}
			if deg, ok := parsedJSON["degraded"].(bool); !ok || !deg {
				t.Fatalf("CLI JSON output failed to include degraded=true: %s", string(jsonBytes))
			}

			// Verify Human rendering announces DEGRADED DECISION on first line
			humanStr := explanation.RenderHuman(doc)
			if !strings.HasPrefix(humanStr, "DEGRADED DECISION:") {
				t.Fatalf("CLI Human output failed to state DEGRADED DECISION on first line:\n%s", humanStr)
			}
		})
	}
}
