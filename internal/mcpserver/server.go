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
	"github.com/aniklavida/installgate/internal/store"
	"github.com/aniklavida/installgate/internal/verdict"
)

var (
	// ErrMCPApprovalForbidden is returned whenever an MCP client attempts to create or mutate approvals.
	ErrMCPApprovalForbidden = errors.New("approvals may only be created by a human at the local machine; MCP agents cannot approve dependencies")
)

// PackageEvaluator evaluates packages against policy without side effects.
type PackageEvaluator interface {
	Evaluate(ctx context.Context, pkg, version string) (*explanation.DecisionDocument, error)
}

// Server implements a read-only/preflight MCP server providing package preflight inspection
// and status checks, while strictly rejecting any approval mutation attempts.
type Server struct {
	store     store.Store
	evaluator PackageEvaluator
	mu        sync.Mutex
}

// NewServer creates a new MCP server.
func NewServer(s store.Store, eval PackageEvaluator) *Server {
	return &Server{
		store:     s,
		evaluator: eval,
	}
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
			"tools": []toolDefinition{
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
			},
		}

	case "tools/call":
		var callParams toolCallParams
		if err := json.Unmarshal(req.Params, &callParams); err != nil {
			resp.Error = &rpcError{Code: -32602, Message: "invalid tool call params"}
			break
		}

		// Security constraint: ANY attempt to call approval tools via MCP must be rejected
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
		default:
			resp.Error = &rpcError{Code: -32601, Message: fmt.Sprintf("tool not found: %s", callParams.Name)}
		}

	case "create_approval", "approve_package", "approve":
		// Direct RPC method attempts to create approvals
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
			"reason":  "mcp clients are strictly forbidden from creating approvals",
			"payload": payload,
		},
	})
}

func isApprovalAttempt(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, "approv") ||
		strings.Contains(lower, "bypass") ||
		strings.Contains(lower, "allowlist")
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
