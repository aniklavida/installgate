package gateway

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aniklavida/installgate/internal/evidence"
	"github.com/aniklavida/installgate/internal/explanation"
	"github.com/aniklavida/installgate/internal/policy"
	"github.com/aniklavida/installgate/internal/store"
	"github.com/aniklavida/installgate/internal/verdict"
)

// SnapshotAssembler coordinates evidence collection to produce an immutable snapshot.
type SnapshotAssembler interface {
	Assemble(ctx context.Context, pkg, version string) (evidence.Snapshot, error)
}

// EngineConfig configures a unified decision engine instance.
type EngineConfig struct {
	Policy    *policy.Policy
	Assembler SnapshotAssembler
	Store     store.Store
	Actor     string
}

// Engine implements the core policy evaluation engine shared by gateway, CLI, and MCP.
type Engine struct {
	policy    *policy.Policy
	assembler SnapshotAssembler
	store     store.Store
	actor     string
}

// NewEngine creates a unified decision engine.
func NewEngine(cfg EngineConfig) *Engine {
	pol := cfg.Policy
	if pol == nil {
		pol = policy.NewDefaultPolicy()
	}
	actor := cfg.Actor
	if actor == "" {
		actor = "engine"
	}
	return &Engine{
		policy:    pol,
		assembler: cfg.Assembler,
		store:     cfg.Store,
		actor:     actor,
	}
}

// Policy returns the engine's active policy.
func (e *Engine) Policy() *policy.Policy {
	return e.policy
}

// Evaluate evaluates a package coordinates request against policy, assembling evidence as needed.
func (e *Engine) Evaluate(ctx context.Context, pkg, version string) (*explanation.DecisionDocument, error) {
	if e.assembler == nil {
		return nil, errors.New("evidence assembler not configured")
	}
	snap, err := e.assembler.Assemble(ctx, pkg, version)
	if err != nil {
		return nil, err
	}
	return e.EvaluateSnapshot(ctx, snap)
}

// EvaluateSnapshot applies the policy directly to an immutable evidence snapshot.
func (e *Engine) EvaluateSnapshot(ctx context.Context, snap evidence.Snapshot) (*explanation.DecisionDocument, error) {
	pkg := snap.Package()
	version := snap.Version()

	dec := e.policy.EvaluateSnapshot(snap)

	// Check for active human approval when policy requires approval
	if dec.Verdict == verdict.ApprovalRequired && e.store != nil {
		if app, ok, _ := e.store.FindActiveApproval(ctx, pkg, version, time.Now().UTC()); ok && app != nil {
			dec.Verdict = verdict.Allow
			dec.Reasons = append(dec.Reasons, verdict.Reason{
				RuleID:  "approval.granted",
				Summary: fmt.Sprintf("active human approval (%s) granted by %s: %s", app.ID, app.Actor, app.Reason),
			})
		}
	}

	doc, err := explanation.NewDecisionDocument(pkg, version, dec, snap)
	if err != nil {
		return nil, err
	}

	if doc != nil && e.store != nil && e.actor != "" {
		_ = e.store.SaveDecision(ctx, doc)
		ruleID := ""
		if len(dec.Reasons) > 0 {
			ruleID = dec.Reasons[0].RuleID
		}
		_ = e.store.AppendAudit(ctx, &store.AuditEvent{
			EventTime:  time.Now().UTC(),
			EventType:  "decision",
			Package:    pkg,
			Version:    version,
			DecisionID: doc.DecisionID,
			RuleID:     ruleID,
			Verdict:    string(doc.Verdict),
			Actor:      e.actor,
			Snapshot:   &snap,
		})
	}

	return doc, nil
}
