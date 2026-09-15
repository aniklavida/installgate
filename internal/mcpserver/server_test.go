package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
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

type mockEvaluator struct {
	doc *explanation.DecisionDocument
	err error
}

func (m *mockEvaluator) Evaluate(ctx context.Context, pkg, version string) (*explanation.DecisionDocument, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.doc != nil {
		return m.doc, nil
	}
	return &explanation.DecisionDocument{
		SchemaVersion: "1",
		DecisionID:    "dec-mcp-1",
		Package:       pkg,
		Version:       version,
		Verdict:       verdict.Allow,
	}, nil
}

func TestMCPRejectsApproval(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "mcp_test.db")

	st, err := store.OpenSQLite(dbPath)
	if err != nil {
		t.Fatalf("failed to open sqlite store: %v", err)
	}
	defer st.Close()

	if err := st.ApplyMigrations(ctx); err != nil {
		t.Fatalf("failed applying migrations: %v", err)
	}

	eval := &mockEvaluator{}
	srv := NewServer(st, eval)

	now := time.Now().UTC()

	// 1. Genuinely attempt an approval through the MCP tool call interface
	approvalToolCalls := []string{
		`{
			"jsonrpc": "2.0",
			"id": 1,
			"method": "tools/call",
			"params": {
				"name": "create_approval",
				"arguments": {
					"package": "malicious-pkg",
					"version": "1.0.0",
					"reason": "agent wants to install",
					"actor": "claude-code"
				}
			}
		}`,
		`{
			"jsonrpc": "2.0",
			"id": 2,
			"method": "tools/call",
			"params": {
				"name": "approve_package",
				"arguments": {
					"package": "another-pkg",
					"version": "2.0.0"
				}
			}
		}`,
		`{
			"jsonrpc": "2.0",
			"id": 3,
			"method": "create_approval",
			"params": {
				"package": "direct-rpc-pkg",
				"version": "3.0.0"
			}
		}`,
	}

	for i, reqJSON := range approvalToolCalls {
		respBytes, err := srv.HandleRequest(ctx, []byte(reqJSON))
		if err != nil {
			t.Fatalf("case %d: unexpected transport error: %v", i, err)
		}

		var resp jsonRPCResponse
		if err := json.Unmarshal(respBytes, &resp); err != nil {
			t.Fatalf("case %d: failed to parse response JSON: %v", i, err)
		}

		if resp.Error == nil {
			t.Fatalf("case %d: expected approval attempt to be rejected, but received success: %s", i, string(respBytes))
		}

		expectedErrSubstr := "approvals may only be created by a human at the local machine"
		if !strings.Contains(resp.Error.Message, expectedErrSubstr) {
			t.Fatalf("case %d: expected error to contain %q, got %q", i, expectedErrSubstr, resp.Error.Message)
		}
	}

	// 2. Assert NO approvals were created in the store
	apps, err := st.ListApprovals(ctx, false, now)
	if err != nil {
		t.Fatalf("failed listing approvals: %v", err)
	}
	if len(apps) != 0 {
		t.Fatalf("expected 0 approvals in store, found %d", len(apps))
	}

	_, active, err := st.FindActiveApproval(ctx, "malicious-pkg", "1.0.0", now)
	if err != nil || active {
		t.Fatalf("expected malicious-pkg to not have active approval: active=%v, err=%v", active, err)
	}

	// 3. Assert rejected attempts were durably audited
	events, err := st.ListAuditEvents(ctx, 10, 0)
	if err != nil {
		t.Fatalf("failed listing audit events: %v", err)
	}
	if len(events) != len(approvalToolCalls) {
		t.Fatalf("expected %d audit events for rejected attempts, got %d", len(approvalToolCalls), len(events))
	}
	for _, ev := range events {
		if ev.EventType != "approval_attempt_rejected" {
			t.Fatalf("expected event_type 'approval_attempt_rejected', got %q", ev.EventType)
		}
	}
}

func TestMCPReadOnlyToolsSucceed(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "mcp_readonly.db")

	st, err := store.OpenSQLite(dbPath)
	if err != nil {
		t.Fatalf("failed to open sqlite store: %v", err)
	}
	defer st.Close()

	if err := st.ApplyMigrations(ctx); err != nil {
		t.Fatalf("failed applying migrations: %v", err)
	}

	eval := &mockEvaluator{
		doc: &explanation.DecisionDocument{
			SchemaVersion: "1",
			DecisionID:    "dec-preflight-1",
			Package:       "express",
			Version:       "4.18.2",
			Verdict:       verdict.Allow,
		},
	}
	srv := NewServer(st, eval)

	// Test tools/list does NOT contain any approval tools
	listReq := `{"jsonrpc":"2.0","id":10,"method":"tools/list"}`
	respBytes, err := srv.HandleRequest(ctx, []byte(listReq))
	if err != nil {
		t.Fatalf("unexpected error calling tools/list: %v", err)
	}
	var listResp struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(respBytes, &listResp); err != nil {
		t.Fatalf("failed parsing tools/list response: %v", err)
	}
	for _, tool := range listResp.Result.Tools {
		if strings.Contains(strings.ToLower(tool.Name), "approv") {
			t.Fatalf("tools/list illegally advertises approval tool: %q", tool.Name)
		}
	}

	// Test check_package tool call
	checkReq := `{
		"jsonrpc": "2.0",
		"id": 11,
		"method": "tools/call",
		"params": {
			"name": "check_package",
			"arguments": {
				"package": "express",
				"version": "4.18.2"
			}
		}
	}`
	respBytes, err = srv.HandleRequest(ctx, []byte(checkReq))
	if err != nil {
		t.Fatalf("check_package error: %v", err)
	}
	var checkResp jsonRPCResponse
	if err := json.Unmarshal(respBytes, &checkResp); err != nil {
		t.Fatalf("failed unmarshaling check_package response: %v", err)
	}
	if checkResp.Error != nil {
		t.Fatalf("check_package returned unexpected error: %v", checkResp.Error)
	}
}

func TestMCPNewTools(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "mcp_new_tools.db")

	st, err := store.OpenSQLite(dbPath)
	if err != nil {
		t.Fatalf("failed opening store: %v", err)
	}
	defer st.Close()

	if err := st.ApplyMigrations(ctx); err != nil {
		t.Fatalf("failed applying migrations: %v", err)
	}

	eval := &mockEvaluator{}
	pol := policy.NewDefaultPolicy()
	srv := NewServer(st, eval, WithPolicy(pol))

	// 1. Test get_policy
	polReq := `{"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"get_policy","arguments":{}}}`
	respBytes, err := srv.HandleRequest(ctx, []byte(polReq))
	if err != nil {
		t.Fatalf("get_policy error: %v", err)
	}
	var polResp jsonRPCResponse
	if err := json.Unmarshal(respBytes, &polResp); err != nil {
		t.Fatalf("failed unmarshaling get_policy response: %v", err)
	}
	if polResp.Error != nil {
		t.Fatalf("get_policy returned error: %v", polResp.Error)
	}
	resMap, ok := polResp.Result.(map[string]any)
	if !ok {
		t.Fatalf("expected map result, got %T", polResp.Result)
	}
	contents, ok := resMap["content"].([]any)
	if !ok || len(contents) == 0 {
		t.Fatalf("expected content in result, got %v", resMap)
	}
	c0 := contents[0].(map[string]any)
	text := c0["text"].(string)
	if !strings.Contains(text, `"profile": "balanced"`) || !strings.Contains(text, `"vulnerability_threshold": "high"`) {
		t.Errorf("get_policy text missing expected policy content: %s", text)
	}

	// 2. Test recent_decisions
	// Pre-populate an audit event of type decision
	now := time.Now().UTC()
	err = st.AppendAudit(ctx, &store.AuditEvent{
		EventTime:  now,
		EventType:  "decision",
		Package:    "react",
		Version:    "18.2.0",
		DecisionID: "dec-audit-test",
		RuleID:     "core.policy-satisfied",
		Verdict:    "allow",
		Actor:      "gateway",
	})
	if err != nil {
		t.Fatalf("failed appending audit: %v", err)
	}

	recentReq := `{"jsonrpc":"2.0","id":21,"method":"tools/call","params":{"name":"recent_decisions","arguments":{"limit":5}}}`
	respBytes, err = srv.HandleRequest(ctx, []byte(recentReq))
	if err != nil {
		t.Fatalf("recent_decisions error: %v", err)
	}
	var recentResp jsonRPCResponse
	if err := json.Unmarshal(respBytes, &recentResp); err != nil {
		t.Fatalf("failed unmarshaling recent_decisions response: %v", err)
	}
	if recentResp.Error != nil {
		t.Fatalf("recent_decisions returned error: %v", recentResp.Error)
	}
	rResMap := recentResp.Result.(map[string]any)
	rContents := rResMap["content"].([]any)
	rText := rContents[0].(map[string]any)["text"].(string)
	if !strings.Contains(rText, "dec-audit-test") || !strings.Contains(rText, "react") {
		t.Errorf("recent_decisions missing populated decision: %s", rText)
	}
}

func TestMCPReadOnlyProof_RuntimeToolsDrivenWithMutations(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "mcp_readonly_proof.db")

	st, err := store.OpenSQLite(dbPath)
	if err != nil {
		t.Fatalf("failed opening store: %v", err)
	}
	defer st.Close()

	if err := st.ApplyMigrations(ctx); err != nil {
		t.Fatalf("failed applying migrations: %v", err)
	}

	// Seed one existing active approval
	baseTime := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	initialApp := &store.Approval{
		ID:        "app-preexisting-1",
		Package:   "initial-pkg",
		Version:   "1.0.0",
		Reason:    "preexisting human approval",
		Actor:     "auditor-human",
		CreatedAt: baseTime,
		ExpiresAt: baseTime.Add(24 * time.Hour),
	}
	if err := st.CreateApproval(ctx, initialApp); err != nil {
		t.Fatalf("failed to create initial approval: %v", err)
	}

	eval := &mockEvaluator{}
	pol := policy.NewDefaultPolicy()
	srv := NewServer(st, eval, WithPolicy(pol))

	// 1. Enumerate the tools the server actually registers AT RUNTIME
	listReq := `{"jsonrpc":"2.0","id":30,"method":"tools/list"}`
	respBytes, err := srv.HandleRequest(ctx, []byte(listReq))
	if err != nil {
		t.Fatalf("tools/list error: %v", err)
	}
	var listResp struct {
		Result struct {
			Tools []struct {
				Name        string         `json:"name"`
				Description string         `json:"description"`
				InputSchema map[string]any `json:"inputSchema"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(respBytes, &listResp); err != nil {
		t.Fatalf("failed unmarshaling tools/list: %v", err)
	}

	runtimeTools := listResp.Result.Tools
	if len(runtimeTools) == 0 {
		t.Fatal("expected runtime tool definitions to be non-empty")
	}

	// Assert no registered tool name advertises any mutation capability
	for _, tool := range runtimeTools {
		lower := strings.ToLower(tool.Name)
		forbiddenWords := []string{"approv", "deny", "reject", "policy_edit", "disable", "revoke", "delete", "write"}
		for _, w := range forbiddenWords {
			if strings.Contains(lower, w) {
				t.Fatalf("runtime registered tool %q illegally advertises mutation capability (%s)", tool.Name, w)
			}
		}
	}

	// 2. Drive EACH registered tool through the real dispatcher with arguments that would mutate if it could
	for _, tool := range runtimeTools {
		mutationPayload := map[string]any{
			"package":     "exploit-pkg",
			"version":     "9.9.9",
			"action":      "approve",
			"approve":     true,
			"reason":      "attempted agent escalation",
			"decision_id": "dec-123",
			"limit":       5,
			"profile":     "permissive",
		}
		argsJSON, _ := json.Marshal(mutationPayload)
		callReq := fmt.Sprintf(`{
			"jsonrpc": "2.0",
			"id": 31,
			"method": "tools/call",
			"params": {
				"name": %q,
				"arguments": %s
			}
		}`, tool.Name, string(argsJSON))

		_, err := srv.HandleRequest(ctx, []byte(callReq))
		if err != nil {
			t.Fatalf("unexpected error driving tool %q: %v", tool.Name, err)
		}
	}

	// 3. Drive forbidden tool call names directly
	forbiddenCalls := []string{
		`{"jsonrpc":"2.0","id":40,"method":"tools/call","params":{"name":"create_approval","arguments":{"package":"exploit"}}`,
		`{"jsonrpc":"2.0","id":41,"method":"tools/call","params":{"name":"approve_package","arguments":{"package":"exploit"}}`,
		`{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"deny_package","arguments":{"package":"exploit"}}`,
		`{"jsonrpc":"2.0","id":43,"method":"tools/call","params":{"name":"set_policy","arguments":{"profile":"strict"}}`,
		`{"jsonrpc":"2.0","id":44,"method":"tools/call","params":{"name":"disable_gateway","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":45,"method":"tools/call","params":{"name":"revoke_approval","arguments":{"id":"app-preexisting-1"}}}`,
		`{"jsonrpc":"2.0","id":46,"method":"create_approval","params":{"package":"direct-rpc"}}`,
		`{"jsonrpc":"2.0","id":47,"method":"deny","params":{"package":"direct-rpc"}}`,
	}
	for i, fCall := range forbiddenCalls {
		respBytes, err := srv.HandleRequest(ctx, []byte(fCall))
		if err != nil {
			t.Fatalf("case %d: unexpected transport error: %v", i, err)
		}
		var r jsonRPCResponse
		_ = json.Unmarshal(respBytes, &r)
		if r.Error == nil {
			t.Fatalf("case %d: expected forbidden call to be rejected, got success", i)
		}
	}

	// 4. Assert the store is 100% UNCHANGED:
	// - no new approval row
	// - no revoked approval
	apps, err := st.ListApprovals(ctx, false, baseTime.Add(time.Hour))
	if err != nil {
		t.Fatalf("failed listing approvals: %v", err)
	}
	if len(apps) != 1 {
		t.Fatalf("READ-ONLY INVARIANT VIOLATION: expected exactly 1 approval in store, found %d", len(apps))
	}
	if apps[0].ID != "app-preexisting-1" {
		t.Fatalf("unexpected approval in store: %v", apps[0])
	}
	if apps[0].RevokedAt != nil {
		t.Fatalf("READ-ONLY INVARIANT VIOLATION: preexisting approval was revoked!")
	}
}

type staticSnapshotAssembler struct {
	snapshots map[string]evidence.Snapshot
}

func (s *staticSnapshotAssembler) Assemble(ctx context.Context, pkg, version string) (evidence.Snapshot, error) {
	key := fmt.Sprintf("%s@%s", pkg, version)
	snap, ok := s.snapshots[key]
	if !ok {
		return evidence.NewSnapshot(pkg, version, nil, nil, time.Now()), nil
	}
	return snap, nil
}

func TestMCPAndGatewayAgreement(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "agreement_test.db")

	st, err := store.OpenSQLite(dbPath)
	if err != nil {
		t.Fatalf("failed opening store: %v", err)
	}
	defer st.Close()

	if err := st.ApplyMigrations(ctx); err != nil {
		t.Fatalf("failed applying migrations: %v", err)
	}

	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	pol := policy.NewDefaultPolicy()

	// Build snapshots covering diverse policy verdicts
	testCases := []struct {
		name            string
		pkg             string
		ver             string
		signals         []verdict.Signal
		expectedVerdict verdict.Kind
	}{
		{
			name:            "Clean package satisfies policy",
			pkg:             "clean-pkg",
			ver:             "1.0.0",
			signals:         nil,
			expectedVerdict: verdict.Allow,
		},
		{
			name: "Critical vulnerability triggers Block",
			pkg:  "vuln-pkg",
			ver:  "2.0.0",
			signals: []verdict.Signal{
				{
					Kind:        evidence.KindVulnerability,
					Source:      "osv",
					Observation: "critical",
					Confidence:  evidence.ConfidenceHigh,
					RetrievedAt: now,
					FreshUntil:  now.Add(time.Hour),
				},
			},
			expectedVerdict: verdict.Block,
		},
		{
			name: "Newborn confusable triggers ApprovalRequired",
			pkg:  "confusable-pkg",
			ver:  "3.0.0",
			signals: []verdict.Signal{
				{
					Kind:        evidence.KindNameConfusion,
					Source:      "typosquat",
					Observation: "confusion_detected:target:express",
					Confidence:  evidence.ConfidenceHigh,
					RetrievedAt: now,
					FreshUntil:  now.Add(time.Hour),
				},
				{
					Kind:        evidence.KindPackageAge,
					Source:      "registry",
					Observation: "newborn",
					Confidence:  evidence.ConfidenceHigh,
					RetrievedAt: now,
					FreshUntil:  now.Add(time.Hour),
				},
			},
			expectedVerdict: verdict.ApprovalRequired,
		},
		{
			name: "Install script triggers Warn under balanced profile",
			pkg:  "script-pkg",
			ver:  "4.0.0",
			signals: []verdict.Signal{
				{
					Kind:        evidence.KindInstallScript,
					Source:      "inspect",
					Observation: "present",
					Confidence:  evidence.ConfidenceHigh,
					RetrievedAt: now,
					FreshUntil:  now.Add(time.Hour),
				},
			},
			expectedVerdict: verdict.Warn,
		},
	}

	// Upstream HTTP server mock for gateway pass-through
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"name":"mock-pkg"}`))
	}))
	defer upstreamServer.Close()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			snap := evidence.NewSnapshot(tc.pkg, tc.ver, tc.signals, nil, now)

			assembler := &staticSnapshotAssembler{
				snapshots: map[string]evidence.Snapshot{
					fmt.Sprintf("%s@%s", tc.pkg, tc.ver): snap,
				},
			}

			engine := gateway.NewEngine(gateway.EngineConfig{
				Policy:    pol,
				Assembler: assembler,
				Store:     st,
				Actor:     "test",
			})

			// 1. Run through the Gateway path
			gwHandler, err := gateway.NewHandler(gateway.Config{
				UpstreamBaseURL: upstreamServer.URL,
				Evaluator:       engine,
				DecisionStore:   st,
			})
			if err != nil {
				t.Fatalf("failed creating gateway handler: %v", err)
			}

			req := httptest.NewRequest("GET", fmt.Sprintf("/%s/%s", tc.pkg, tc.ver), nil)
			rec := httptest.NewRecorder()
			gwHandler.ServeHTTP(rec, req)

			// Gateway verdict derived from gateway evaluation
			gatewayDoc, err := engine.Evaluate(ctx, tc.pkg, tc.ver)
			if err != nil {
				t.Fatalf("gateway evaluation failed: %v", err)
			}
			gatewayVerdict := gatewayDoc.Verdict

			// 2. Run through the MCP path
			mcpServer := NewServer(st, engine, WithPolicy(pol))
			mcpCall := fmt.Sprintf(`{
				"jsonrpc": "2.0",
				"id": 100,
				"method": "tools/call",
				"params": {
					"name": "check_package",
					"arguments": {
						"package": %q,
						"version": %q
					}
				}
			}`, tc.pkg, tc.ver)

			respBytes, err := mcpServer.HandleRequest(ctx, []byte(mcpCall))
			if err != nil {
				t.Fatalf("mcp call error: %v", err)
			}

			var mcpResp jsonRPCResponse
			if err := json.Unmarshal(respBytes, &mcpResp); err != nil {
				t.Fatalf("failed unmarshaling mcp response: %v", err)
			}
			if mcpResp.Error != nil {
				t.Fatalf("mcp check_package returned unexpected error: %v", mcpResp.Error)
			}

			mcpResultMap := mcpResp.Result.(map[string]any)
			contentSlice := mcpResultMap["content"].([]any)
			text := contentSlice[0].(map[string]any)["text"].(string)

			var mcpDoc explanation.DecisionDocument
			if err := json.Unmarshal([]byte(text), &mcpDoc); err != nil {
				t.Fatalf("failed unmarshaling mcp DecisionDocument JSON: %v", err)
			}

			// 3. Compare verdicts — PROOF of agreement
			if gatewayVerdict != mcpDoc.Verdict {
				t.Fatalf("DISAGREEMENT: gateway verdict was %q but MCP verdict was %q for identical snapshot",
					gatewayVerdict, mcpDoc.Verdict)
			}
			if gatewayDoc.DecisionID != mcpDoc.DecisionID {
				t.Fatalf("DISAGREEMENT: gateway decision ID %q != MCP decision ID %q",
					gatewayDoc.DecisionID, mcpDoc.DecisionID)
			}
			if tc.expectedVerdict != mcpDoc.Verdict {
				t.Fatalf("expected verdict %q, got %q", tc.expectedVerdict, mcpDoc.Verdict)
			}
		})
	}
}
