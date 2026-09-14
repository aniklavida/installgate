package evidence

import (
	"context"
	"time"

	"github.com/aniklavida/installgate/internal/verdict"
)

// State represents the outcome state of an evidence provider.
type State string

const (
	StateAvailable   State = "available"
	StateStale       State = "stale"
	StateDegraded    State = "degraded"
	StateUnavailable State = "unavailable"
)

// Valid reports whether s is one of the four explicit provider states.
func (s State) Valid() bool {
	switch s {
	case StateAvailable, StateStale, StateDegraded, StateUnavailable:
		return true
	default:
		return false
	}
}

// Query defines the package coordinates submitted to an evidence provider.
type Query struct {
	Package string
	Version string
}

// Outcome captures the result of querying an evidence provider.
// The zero value of Outcome is safely treated as StateUnavailable.
type Outcome struct {
	state       State
	kind        string
	source      string
	signals     []verdict.Signal
	err         error
	retrievedAt time.Time
	freshUntil  time.Time
	reason      string
}

// NewAvailableOutcome constructs an available outcome with verified observations.
func NewAvailableOutcome(kind, source string, signals []verdict.Signal, retrievedAt, freshUntil time.Time) Outcome {
	copied := make([]verdict.Signal, len(signals))
	copy(copied, signals)
	return Outcome{
		state:       StateAvailable,
		kind:        kind,
		source:      source,
		signals:     copied,
		retrievedAt: normalizeTime(retrievedAt),
		freshUntil:  normalizeTime(freshUntil),
	}
}

// NewStaleOutcome constructs a stale-but-usable outcome with explanatory rationale.
func NewStaleOutcome(kind, source string, signals []verdict.Signal, retrievedAt, freshUntil time.Time, reason string) Outcome {
	copied := make([]verdict.Signal, len(signals))
	copy(copied, signals)
	return Outcome{
		state:       StateStale,
		kind:        kind,
		source:      source,
		signals:     copied,
		retrievedAt: normalizeTime(retrievedAt),
		freshUntil:  normalizeTime(freshUntil),
		reason:      reason,
	}
}

// NewDegradedOutcome constructs an outcome when partial or reduced-confidence evidence was obtained.
func NewDegradedOutcome(kind, source string, signals []verdict.Signal, retrievedAt, freshUntil time.Time, reason string) Outcome {
	copied := make([]verdict.Signal, len(signals))
	copy(copied, signals)
	return Outcome{
		state:       StateDegraded,
		kind:        kind,
		source:      source,
		signals:     copied,
		retrievedAt: normalizeTime(retrievedAt),
		freshUntil:  normalizeTime(freshUntil),
		reason:      reason,
	}
}

// NewUnavailableOutcome constructs an unavailable outcome indicating provider failure.
// Any downstream consumers will visibly observe that evidence is unavailable.
func NewUnavailableOutcome(kind, source string, err error, retrievedAt time.Time) Outcome {
	norm := normalizeTime(retrievedAt)
	return Outcome{
		state:       StateUnavailable,
		kind:        kind,
		source:      source,
		err:         err,
		retrievedAt: norm,
		freshUntil:  norm,
	}
}

// State returns the outcome state. The zero value defaults to StateUnavailable.
func (o Outcome) State() State {
	if !o.state.Valid() {
		return StateUnavailable
	}
	return o.state
}

// Kind returns the evidence kind provided.
func (o Outcome) Kind() string {
	return o.kind
}

// Source returns the source identifier of the provider.
func (o Outcome) Source() string {
	return o.source
}

// Signals returns a copy of observations. If the outcome is unavailable and no signals
// were supplied, an explicit unavailable signal is returned so the failure is never silent.
func (o Outcome) Signals() []verdict.Signal {
	if o.State() == StateUnavailable && len(o.signals) == 0 {
		return []verdict.Signal{
			{
				Kind:        o.kind,
				Source:      o.source,
				Observation: "unavailable",
				Confidence:  ConfidenceNone,
				RetrievedAt: o.retrievedAt,
				FreshUntil:  o.freshUntil,
			},
		}
	}
	res := make([]verdict.Signal, len(o.signals))
	copy(res, o.signals)
	return res
}

// Err returns the underlying error when unavailable, or nil.
func (o Outcome) Err() error {
	return o.err
}

// RetrievedAt returns the observation retrieval timestamp in UTC.
func (o Outcome) RetrievedAt() time.Time {
	return o.retrievedAt
}

// FreshUntil returns the timestamp when freshness expires in UTC.
func (o Outcome) FreshUntil() time.Time {
	return o.freshUntil
}

// Reason returns the optional rationale for stale or degraded states.
func (o Outcome) Reason() string {
	return o.reason
}

// IsAvailable reports whether the state is available.
func (o Outcome) IsAvailable() bool {
	return o.State() == StateAvailable
}

// IsStale reports whether the state is stale.
func (o Outcome) IsStale() bool {
	return o.State() == StateStale
}

// IsDegraded reports whether the state is degraded.
func (o Outcome) IsDegraded() bool {
	return o.State() == StateDegraded
}

// IsUnavailable reports whether the state is unavailable.
func (o Outcome) IsUnavailable() bool {
	return o.State() == StateUnavailable
}

// Provider defines the interface for evidence collectors.
type Provider interface {
	Name() string
	Kind() string
	Provide(ctx context.Context, q Query) Outcome
}
