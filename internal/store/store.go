package store

import (
	"context"
	"errors"
	"time"

	"github.com/aniklavida/installgate/internal/evidence"
	"github.com/aniklavida/installgate/internal/explanation"
	"github.com/aniklavida/installgate/internal/verdict"
)

var (
	// ErrApprovalNotFound indicates the requested approval does not exist.
	ErrApprovalNotFound = errors.New("approval not found")

	// ErrApprovalExpired indicates the approval exists but has expired.
	ErrApprovalExpired = errors.New("approval expired")

	// ErrNonHumanActor indicates an attempt to create an approval by an agent or automated client.
	ErrNonHumanActor = errors.New("approvals may only be created by a human at the local machine")

	// ErrAuditAppendOnly indicates a violation of the append-only audit invariant.
	ErrAuditAppendOnly = errors.New("audit log is append-only: modifications and deletions are forbidden")
)

// Approval represents an expiring, human-attributed policy exception.
type Approval struct {
	ID        string     `json:"id"`
	Package   string     `json:"package"`
	Version   string     `json:"version"` // exact version or semver range / "*"
	Reason    string     `json:"reason"`
	Actor     string     `json:"actor"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// IsActive returns true if the approval has not expired at reference time `now` and has not been revoked.
func (a *Approval) IsActive(now time.Time) bool {
	if a == nil {
		return false
	}
	if a.RevokedAt != nil && !now.Before(*a.RevokedAt) {
		return false
	}
	return now.Before(a.ExpiresAt)
}

// AuditEvent represents an immutable record of an evaluation, decision, approval, or lifecycle change.
type AuditEvent struct {
	ID         int64              `json:"id"`
	EventTime  time.Time          `json:"event_time"`
	EventType  string             `json:"event_type"` // e.g. "decision", "approval_created", "config_changed"
	Package    string             `json:"package,omitempty"`
	Version    string             `json:"version,omitempty"`
	DecisionID string             `json:"decision_id,omitempty"`
	RuleID     string             `json:"rule_id,omitempty"`
	Verdict    string             `json:"verdict,omitempty"`
	Actor      string             `json:"actor,omitempty"`
	Metadata   map[string]string  `json:"metadata,omitempty"`
	Snapshot   *evidence.Snapshot `json:"snapshot,omitempty"`
}

// ConfigRecord represents a stored configuration history entry.
type ConfigRecord struct {
	ID        int64     `json:"id"`
	Action    string    `json:"action"`
	Phase     string    `json:"phase"`
	Payload   string    `json:"payload"`
	CreatedAt time.Time `json:"created_at"`
}

// DecisionRecord represents a stored decision with reconstructed explanation document.
type DecisionRecord struct {
	DecisionID string                        `json:"decision_id"`
	Package    string                        `json:"package"`
	Version    string                        `json:"version"`
	Verdict    verdict.Kind                  `json:"verdict"`
	Reason     string                        `json:"reason"`
	RuleID     string                        `json:"rule_id"`
	Document   *explanation.DecisionDocument `json:"document"`
	CreatedAt  time.Time                     `json:"created_at"`
}

// Store defines the pluggable persistence contract for InstallGate.
// Implementing this interface separates SQLite or any alternative backend
// from core gateway, policy, and CLI logic.
type Store interface {
	// Close releases any database handles and resources.
	Close() error

	// Migrations
	CurrentSchemaVersion(ctx context.Context) (int, error)
	ApplyMigrations(ctx context.Context) error

	// Approvals
	CreateApproval(ctx context.Context, app *Approval) error
	GetApproval(ctx context.Context, id string) (*Approval, error)
	FindActiveApproval(ctx context.Context, pkg, version string, now time.Time) (*Approval, bool, error)
	ListApprovals(ctx context.Context, activeOnly bool, now time.Time) ([]*Approval, error)
	RevokeApproval(ctx context.Context, id string, revokedAt time.Time) error

	// Audit log (strictly append-only)
	AppendAudit(ctx context.Context, event *AuditEvent) error
	ListAuditEvents(ctx context.Context, limit, offset int) ([]*AuditEvent, error)
	GetAuditEvent(ctx context.Context, id int64) (*AuditEvent, error)
	FindAuditByDecision(ctx context.Context, decisionID string) (*AuditEvent, error)

	// Decisions
	SaveDecision(ctx context.Context, doc *explanation.DecisionDocument) error
	GetDecision(ctx context.Context, decisionID string) (*explanation.DecisionDocument, error)

	// Config history
	RecordConfigHistory(ctx context.Context, action, phase, payload string) error
	ListConfigHistory(ctx context.Context, limit int) ([]*ConfigRecord, error)

	// Evidence Cache persistence & rebuild
	SaveCachedEvidence(ctx context.Context, pkg, version, kind string, outcome evidence.Outcome, staleUntil time.Time) error
	GetCachedEvidence(ctx context.Context, kind, pkg, version string, now time.Time) (evidence.Outcome, bool, error)
	SaveCachedAllow(ctx context.Context, pkg, version string, d verdict.Decision, snapshotID string, retrievedAt, freshUntil, staleUntil time.Time) error
	GetCachedAllow(ctx context.Context, pkg, version string, now time.Time) (evidence.CachedAllow, bool, error)
	ClearEvidenceCache(ctx context.Context) error

	// Backup and Restore
	Backup(ctx context.Context, destPath string) error
	Vacuum(ctx context.Context) error
}
