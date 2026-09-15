package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/aniklavida/installgate/internal/explanation"
	"github.com/aniklavida/installgate/internal/policy"
	"github.com/aniklavida/installgate/internal/store"
	"github.com/aniklavida/installgate/internal/verdict"
)

var (
	// ErrMCPApprovalForbidden is returned whenever an MCP client attempts to mutate approvals, denials, policy, or gateway state.
	ErrMCPApprovalForbidden = errors.New("approvals may only be created by a human at the local machine; MCP agents cannot mutate policy, approvals, or gateway state")
)

// PackageEvaluator evaluates packages against policy without side effects.
type PackageEvaluator interface {
	Evaluate(ctx context.Context, pkg, version string) (*explanation.DecisionDocument, error)
}

// Option configures an MCP server instance.
type Option func(*Server)

// WithPolicy configures a custom policy on the MCP server.
func WithPolicy(p *policy.Policy) Option {
	return func(s *Server) {
		s.policy = p
	}
}

// Server implements a read-only/preflight MCP server providing package preflight inspection
// and status checks, while strictly rejecting any approval mutation attempts.
type Server struct {
	store     store.Store
	evaluator PackageEvaluator
	policy    *policy.Policy
	mu        sync.Mutex
}

// NewServer creates a new MCP server.
func NewServer(s store.Store, eval PackageEvaluator, opts ...Option) *Server {
	srv := &Server{
		store:     s,
		evaluator: eval,
	}
	for _, opt := range opts {
		opt(srv)
	}
	return srv
}

type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonRPCResponse struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      any       `json:"id"`
	Result  any       `json:"result,omitempty"`
	Error   *rpcError `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type toolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

type toolDefinition struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

type toolCallResult struct {
	Content []toolContent `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}

type toolContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// HandleRequest processes a single JSON-RPC request and returns the response.
func (s *Server) HandleRequest(ctx context.Context, reqBytes []byte) ([]byte, error) {
	var req jsonRPCRequest
	if err := json.Unmarshal(reqBytes, &req); err != nil {
		resp := jsonRPCResponse{
			JSONRPC: "2.0",
			Error:   &rpcError{Code: -32700, Message: "parse error: invalid JSON"},
		}
		return json.Marshal(resp)
	}

	resp := jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
	}

	switch req.Method {
	case "initialize":
		resp.Result = map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities": map[string]any{
				"tools": map[string]any{},
			},
			"serverInfo": map[string]string{
				"name":    "installgate-mcp",
				"version": "1.0.0",
			},
		}

	case "tools/list":
		resp.Result = map[string]any{
			"tools": s.RegisteredToolDefinitions(),
		}

	case "tools/call":
		var callParams toolCallParams
		if err := json.Unmarshal(req.Params, &callParams); err != nil {
			resp.Error = &rpcError{Code: -32602, Message: "invalid tool call params"}
			break
		}

		// Security constraint: ANY attempt to call approval, denial, or mutation tools via MCP must be rejected
		if isApprovalAttempt(callParams.Name) {
			s.recordRejectedApprovalAttempt(ctx, "mcp_client", string(callParams.Arguments))
			resp.Error = &rpcError{
				Code:    -32000,
				Message: ErrMCPApprovalForbidden.Error(),
			}
			break
		}

		switch callParams.Name {
		case "check_package":
			res, err := s.handleCheckPackage(ctx, callParams.Arguments)
			if err != nil {
				resp.Error = &rpcError{Code: -32603, Message: err.Error()}
			} else {
				resp.Result = res
			}
		case "explain_decision":
			res, err := s.handleExplainDecision(ctx, callParams.Arguments)
			if err != nil {
				resp.Error = &rpcError{Code: -32603, Message: err.Error()}
			} else {
				resp.Result = res
			}
		case "get_policy":
			res, err := s.handleGetPolicy(ctx, callParams.Arguments)
			if err != nil {
				resp.Error = &rpcError{Code: -32603, Message: err.Error()}
			} else {
				resp.Result = res
			}
		case "recent_decisions":
			res, err := s.handleRecentDecisions(ctx, callParams.Arguments)
			if err != nil {
				resp.Error = &rpcError{Code: -32603, Message: err.Error()}
			} else {
				resp.Result = res
			}
		default:
			resp.Error = &rpcError{Code: -32601, Message: fmt.Sprintf("tool not found: %s", callParams.Name)}
		}

	case "create_approval", "approve_package", "approve", "deny", "deny_package", "revoke", "revoke_approval", "set_policy", "edit_policy", "update_policy", "disable", "disable_gateway":
		// Direct RPC method attempts to mutate approvals, policy, or gateway state
		s.recordRejectedApprovalAttempt(ctx, "mcp_client", string(req.Params))
		resp.Error = &rpcError{
			Code:    -32000,
			Message: ErrMCPApprovalForbidden.Error(),
		}

	default:
		resp.Error = &rpcError{Code: -32601, Message: fmt.Sprintf("method not found: %s", req.Method)}
	}

	return json.Marshal(resp)
}

func (s *Server) handleCheckPackage(ctx context.Context, args json.RawMessage) (*toolCallResult, error) {
	if s.evaluator == nil {
		return nil, errors.New("package evaluator not configured")
	}

	var params struct {
		Package string `json:"package"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	if params.Package == "" || params.Version == "" {
		return nil, errors.New("package and version are required")
	}

	doc, err := s.evaluator.Evaluate(ctx, params.Package, params.Version)
	if err != nil {
		return nil, fmt.Errorf("evaluation error: %w", err)
	}

	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}

	return &toolCallResult{
		Content: []toolContent{
			{
				Type: "text",
				Text: string(data),
			},
		},
	}, nil
}

func (s *Server) handleExplainDecision(ctx context.Context, args json.RawMessage) (*toolCallResult, error) {
	if s.store == nil {
		return nil, errors.New("store not configured")
	}

	var params struct {
		DecisionID string `json:"decision_id"`
	}
	if err := json.Unmarshal(args, &params); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	if params.DecisionID == "" {
		return nil, errors.New("decision_id is required")
	}

	doc, err := s.store.GetDecision(ctx, params.DecisionID)
	if err != nil {
		return nil, fmt.Errorf("failed retrieving decision %s: %w", params.DecisionID, err)
	}

	human := explanation.RenderHuman(doc)
	return &toolCallResult{
		Content: []toolContent{
			{
				Type: "text",
				Text: human,
			},
		},
	}, nil
}

// RegisteredToolDefinitions returns all tool definitions registered at runtime.
func (s *Server) RegisteredToolDefinitions() []toolDefinition {
	return []toolDefinition{
		{
			Name:        "check_package",
			Description: "Preflight evaluation of an npm package and version against InstallGate security policy.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"package": map[string]string{"type": "string", "description": "The npm package name"},
					"version": map[string]string{"type": "string", "description": "The npm package version"},
				},
				"required": []string{"package", "version"},
			},
		},
		{
			Name:        "explain_decision",
			Description: "Retrieve deterministic explanation document for a previous decision.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"decision_id": map[string]string{"type": "string", "description": "The decision identifier"},
				},
				"required": []string{"decision_id"},
			},
		},
		{
			Name:        "get_policy",
			Description: "Retrieve active repository security policy configuration and policy bounds.",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			Name:        "recent_decisions",
			Description: "Retrieve recent policy evaluation decisions from the audit log.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"limit": map[string]any{
						"type":        "integer",
						"description": "Maximum number of recent decisions to return (default 10, max 50)",
					},
				},
			},
		},
	}
}

func (s *Server) handleGetPolicy(ctx context.Context, _ json.RawMessage) (*toolCallResult, error) {
	pol := s.policy
	if pol == nil {
		p, err := policy.LoadDefaultPolicy(".")
		if err != nil || p == nil {
			p = policy.NewDefaultPolicy()
		}
		pol = p
	}

	res := map[string]any{
		"version":                 pol.Version,
		"profile":                 pol.Profile,
		"vulnerability_threshold": pol.VulnerabilityThreshold,
		"bounds":                  pol.BoundsStatement(),
	}

	data, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return nil, err
	}

	return &toolCallResult{
		Content: []toolContent{
			{
				Type: "text",
				Text: string(data),
			},
		},
	}, nil
}

func (s *Server) handleRecentDecisions(ctx context.Context, args json.RawMessage) (*toolCallResult, error) {
	if s.store == nil {
		return nil, errors.New("store not configured")
	}

	limit := 10
	if len(args) > 0 && string(args) != "{}" && string(args) != "null" {
		var params struct {
			Limit int `json:"limit"`
		}
		if err := json.Unmarshal(args, &params); err == nil && params.Limit > 0 {
			limit = params.Limit
		}
	}
	if limit > 50 {
		limit = 50
	}

	events, err := s.store.ListAuditEvents(ctx, 100, 0)
	if err != nil {
		return nil, fmt.Errorf("failed listing audit events: %w", err)
	}

	type decisionSummary struct {
		EventTime  string `json:"event_time"`
		DecisionID string `json:"decision_id"`
		Package    string `json:"package"`
		Version    string `json:"version"`
		Verdict    string `json:"verdict"`
		RuleID     string `json:"rule_id"`
		Actor      string `json:"actor"`
	}

	var decs []decisionSummary
	for _, ev := range events {
		if ev.EventType == "decision" {
			decs = append(decs, decisionSummary{
				EventTime:  ev.EventTime.Format(time.RFC3339),
				DecisionID: ev.DecisionID,
				Package:    ev.Package,
				Version:    ev.Version,
				Verdict:    ev.Verdict,
				RuleID:     ev.RuleID,
				Actor:      ev.Actor,
			})
			if len(decs) >= limit {
				break
			}
		}
	}
	if decs == nil {
		decs = []decisionSummary{}
	}

	data, err := json.MarshalIndent(decs, "", "  ")
	if err != nil {
		return nil, err
	}

	return &toolCallResult{
		Content: []toolContent{
			{
				Type: "text",
				Text: string(data),
			},
		},
	}, nil
}

func (s *Server) recordRejectedApprovalAttempt(ctx context.Context, actor, payload string) {
	if s.store == nil {
		return
	}
	_ = s.store.AppendAudit(ctx, &store.AuditEvent{
		EventTime: time.Now().UTC(),
		EventType: "approval_attempt_rejected",
		Actor:     actor,
		Verdict:   string(verdict.Block),
		Metadata: map[string]string{
			"reason":  "mcp clients are strictly forbidden from creating approvals or mutating state",
			"payload": payload,
		},
	})
}

func isApprovalAttempt(name string) bool {
	lower := strings.ToLower(name)
	switch lower {
	case "check_package", "explain_decision", "get_policy", "recent_decisions":
		return false
	}
	return strings.Contains(lower, "approv") ||
		strings.Contains(lower, "deny") ||
		strings.Contains(lower, "reject") ||
		strings.Contains(lower, "policy") ||
		strings.Contains(lower, "disable") ||
		strings.Contains(lower, "bypass") ||
		strings.Contains(lower, "allowlist") ||
		strings.Contains(lower, "revoke") ||
		strings.Contains(lower, "delete") ||
		strings.Contains(lower, "write") ||
		strings.Contains(lower, "edit") ||
		strings.Contains(lower, "mutate") ||
		strings.Contains(lower, "set_") ||
		strings.Contains(lower, "update_") ||
		strings.Contains(lower, "create_")
}

// ServeStdio runs the MCP JSON-RPC loop over standard input/output.
func (s *Server) ServeStdio(ctx context.Context, in io.Reader, out io.Writer) error {
	dec := json.NewDecoder(in)
	enc := json.NewEncoder(out)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}

		respBytes, err := s.HandleRequest(ctx, raw)
		if err != nil {
			return err
		}

		var respObj any
		if err := json.Unmarshal(respBytes, &respObj); err != nil {
			return err
		}
		if err := enc.Encode(respObj); err != nil {
			return err
		}
	}
}

// ServeHTTP implements an HTTP handler for MCP JSON-RPC requests.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	resp, err := s.HandleRequest(r.Context(), body)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(resp)
}
