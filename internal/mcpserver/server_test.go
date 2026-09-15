package mcpserver

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aniklavida/installgate/internal/explanation"
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
