package mcpserver

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
	"github.com/aniklavida/installgate/internal/gateway"
	"github.com/aniklavida/installgate/internal/policy"
	"github.com/aniklavida/installgate/internal/store"
	"github.com/aniklavida/installgate/internal/verdict"
)

// TestEmptyAdvisoryResponseCannotProduceCleanAllow_MCP proves that an advisory provider returning
// HTTP 200 with [] can NEVER produce a clean allow at the MCP surface (check_package tool),
// and that the degraded flag survives into the tool output.
func TestEmptyAdvisoryResponseCannotProduceCleanAllow_MCP(t *testing.T) {
	now := time.Date(2026, 9, 15, 14, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	// 1. Mock registry
	regServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"name": "mcp-empty-adv-pkg",
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

	// 2. Mock advisory provider returning HTTP 200 OK with []
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
			name:            "MCP_NoCache_Balanced_ApprovalRequired",
			profile:         policy.Balanced,
			withFreshCache:  false,
			expectedVerdict: verdict.ApprovalRequired,
			expectedRuleID:  "availability.no-cache",
		},
		{
			name:            "MCP_NoCache_Strict_Blocked",
			profile:         policy.Strict,
			withFreshCache:  false,
			expectedVerdict: verdict.Block,
			expectedRuleID:  "availability.strict",
		},
		{
			name:            "MCP_FreshCache_Balanced_DegradedAllowWithWarning",
			profile:         policy.Balanced,
			withFreshCache:  true,
			expectedVerdict: verdict.Allow,
			expectedRuleID:  "availability.fresh-cache",
		},
		{
			name:            "MCP_FreshCache_Strict_ApprovalRequired",
			profile:         policy.Strict,
			withFreshCache:  true,
			expectedVerdict: verdict.ApprovalRequired,
			expectedRuleID:  "availability.fresh-cache",
		},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			tempDir := t.TempDir()
			dbPath := filepath.Join(tempDir, "mcp_test.db")
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
					"mcp-empty-adv-pkg",
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
				Actor:     "mcp",
			})

			srv := NewServer(dbStore, engine, WithPolicy(pol))

			ctx := context.Background()
			toolCallJSON := `{
				"jsonrpc": "2.0",
				"id": 101,
				"method": "tools/call",
				"params": {
					"name": "check_package",
					"arguments": {
						"package": "mcp-empty-adv-pkg",
						"version": "1.0.0"
					}
				}
			}`

			respBytes, err := srv.HandleRequest(ctx, []byte(toolCallJSON))
			if err != nil {
				t.Fatalf("HandleRequest failed: %v", err)
			}

			var rpcResp struct {
				JSONRPC string `json:"jsonrpc"`
				ID      int    `json:"id"`
				Result  struct {
					Content []struct {
						Type string `json:"type"`
						Text string `json:"text"`
					} `json:"content"`
					IsError bool `json:"isError,omitempty"`
				} `json:"result"`
			}
			if err := json.Unmarshal(respBytes, &rpcResp); err != nil {
				t.Fatalf("failed unmarshaling MCP response: %v\nbody: %s", err, string(respBytes))
			}

			if len(rpcResp.Result.Content) == 0 {
				t.Fatalf("expected non-empty content in MCP tool call response: %s", string(respBytes))
			}

			contentText := rpcResp.Result.Content[0].Text

			// Parse embedded decision document JSON from MCP content
			var doc struct {
				Verdict  verdict.Kind `json:"verdict"`
				Degraded bool         `json:"degraded"`
				Reasons  []struct {
					RuleID  string `json:"rule_id"`
					Summary string `json:"summary"`
				} `json:"reasons"`
			}
			if err := json.Unmarshal([]byte(contentText), &doc); err != nil {
				t.Fatalf("failed unmarshaling embedded decision doc in MCP content: %v\ncontent: %s", err, contentText)
			}

			// PROVE: Never a clean allow!
			if doc.Verdict == verdict.Allow && !doc.Degraded {
				t.Fatalf("SECURITY FAILURE: MCP check_package produced clean allow from empty advisory response! doc: %+v", doc)
			}

			if doc.Verdict != sc.expectedVerdict {
				t.Fatalf("expected verdict %q, got %q", sc.expectedVerdict, doc.Verdict)
			}

			if len(doc.Reasons) == 0 || doc.Reasons[0].RuleID != sc.expectedRuleID {
				t.Fatalf("expected rule ID %q, got: %+v", sc.expectedRuleID, doc.Reasons)
			}

			if !doc.Degraded {
				t.Fatalf("expected Degraded=true in MCP decision, got false")
			}

			if !strings.Contains(contentText, `"degraded": true`) {
				t.Fatalf("MCP content text does not contain '\"degraded\": true': %s", contentText)
			}
		})
	}
}
