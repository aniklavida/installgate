package verdict

import "time"

// Kind is the action InstallGate requires for an assessed package version.
type Kind string

const (
	Allow            Kind = "allow"
	Warn             Kind = "warn"
	ApprovalRequired Kind = "approval_required"
	Block            Kind = "block"
)

// Signal is one evidence observation used by policy evaluation.
type Signal struct {
	Kind        string    `json:"kind"`
	Source      string    `json:"source"`
	Observation string    `json:"observation"`
	Confidence  string    `json:"confidence"`
	RetrievedAt time.Time `json:"retrieved_at"`
	FreshUntil  time.Time `json:"fresh_until"`
}

// Reason explains a policy rule that contributed to a decision.
type Reason struct {
	RuleID      string   `json:"rule_id"`
	Summary     string   `json:"summary"`
	SignalKinds []string `json:"signal_kinds,omitempty"`
}

// Decision is the deterministic result for one package version and evidence snapshot.
type Decision struct {
	Verdict  Kind     `json:"verdict"`
	Reasons  []Reason `json:"reasons"`
	Degraded bool     `json:"degraded"`
}
