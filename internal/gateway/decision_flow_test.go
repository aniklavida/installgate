package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aniklavida/installgate/internal/evidence"
	"github.com/aniklavida/installgate/internal/explanation"
	"github.com/aniklavida/installgate/internal/verdict"
)

func TestBlockedInstallSurfacesResolvableDecisionIdentifier(t *testing.T) {
	tempDir := t.TempDir()
	store, err := explanation.NewFileStore(tempDir)
	if err != nil {
		t.Fatalf("failed to create FileStore: %v", err)
	}

	evaluator := EvaluatorFunc(func(ctx context.Context, pkg, version string) (*explanation.DecisionDocument, error) {
		if pkg == "blocked-pkg" {
			now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
			signals := []verdict.Signal{
				{
					Kind:        evidence.KindVulnerability,
					Source:      "osv",
					Observation: "critical",
					Confidence:  evidence.ConfidenceHigh,
					RetrievedAt: now,
					FreshUntil:  now.Add(1 * time.Hour),
				},
			}
			states := map[string]evidence.State{
				evidence.KindVulnerability: evidence.StateAvailable,
			}
			snap := evidence.NewSnapshot(pkg, version, signals, states, now)
			dec := verdict.Decision{
				Verdict: verdict.Block,
				Reasons: []verdict.Reason{
					{
						RuleID:      "core.vulnerability-threshold",
						Summary:     "vulnerability exceeds the configured threshold",
						SignalKinds: []string{evidence.KindVulnerability},
					},
				},
			}
			return explanation.NewDecisionDocument(pkg, version, dec, snap, explanation.WithReferenceTime(now))
		}
		return nil, nil
	})

	handler, err := NewHandler(Config{
		UpstreamBaseURL: "https://registry.npmjs.org",
		Evaluator:       evaluator,
		DecisionStore:   store,
	})
	if err != nil {
		t.Fatalf("NewHandler failed: %v", err)
	}

	server := httptest.NewServer(handler)
	defer server.Close()

	// Package manager requests tarball for blocked package
	resp, err := http.Get(server.URL + "/blocked-pkg/-/blocked-pkg-1.0.0.tgz")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected status 403 Forbidden, got %d", resp.StatusCode)
	}

	// 1. Surface decision identifier in header
	decID := resp.Header.Get("X-InstallGate-Decision")
	if decID == "" {
		t.Fatal("expected X-InstallGate-Decision header to be present")
	}
	if !strings.HasPrefix(decID, "dec_") {
		t.Fatalf("expected decision ID to have 'dec_' prefix, got: %q", decID)
	}

	// 2. Surface decision identifier in response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	var errPayload map[string]string
	if err := json.Unmarshal(bodyBytes, &errPayload); err != nil {
		t.Fatalf("expected json response body: %v\nbody: %s", err, string(bodyBytes))
	}

	if errPayload["decision_id"] != decID {
		t.Errorf("expected payload decision_id %q, got %q", decID, errPayload["decision_id"])
	}
	if !strings.Contains(errPayload["error"], "installgate explain "+decID) {
		t.Errorf("expected error message to direct developer to 'installgate explain %s', got: %s", decID, errPayload["error"])
	}

	// 3. Resolve decision identifier back to full decision
	resolvedDoc, err := store.Get(decID)
	if err != nil {
		t.Fatalf("failed to resolve decision ID %q: %v", decID, err)
	}

	if resolvedDoc.DecisionID != decID {
		t.Errorf("resolved ID = %q, want %q", resolvedDoc.DecisionID, decID)
	}
	if resolvedDoc.Package != "blocked-pkg" {
		t.Errorf("resolved Package = %q, want 'blocked-pkg'", resolvedDoc.Package)
	}
	if resolvedDoc.Version != "1.0.0" {
		t.Errorf("resolved Version = %q, want '1.0.0'", resolvedDoc.Version)
	}
	if resolvedDoc.Verdict != verdict.Block {
		t.Errorf("resolved Verdict = %q, want 'block'", resolvedDoc.Verdict)
	}
	if len(resolvedDoc.Reasons) != 1 || resolvedDoc.Reasons[0].RuleID != "core.vulnerability-threshold" {
		t.Errorf("unexpected reasons: %+v", resolvedDoc.Reasons)
	}

	// 4. Verify human rendering
	human := explanation.RenderHuman(resolvedDoc)
	if !strings.Contains(human, decID) {
		t.Errorf("human rendering missing decision ID: %s", human)
	}
	if !strings.Contains(human, "core.vulnerability-threshold") {
		t.Errorf("human rendering missing rule ID: %s", human)
	}
}
