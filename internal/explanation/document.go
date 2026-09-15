package explanation

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aniklavida/installgate/internal/evidence"
	"github.com/aniklavida/installgate/internal/verdict"
)

// CurrentSchemaVersion is the JSON decision document compatibility schema version.
const CurrentSchemaVersion = "1"

// EvidenceRecord represents one evidence observation linked to a decision reason.
type EvidenceRecord struct {
	Kind          string    `json:"kind"`
	Source        string    `json:"source"`
	ObservedValue string    `json:"observed_value"`
	Confidence    string    `json:"confidence"`
	RetrievedAt   time.Time `json:"retrieved_at"`
	FreshUntil    time.Time `json:"fresh_until"`
	Freshness     string    `json:"freshness"`
}

// ReasonExplanation pairs a rule identifier with its summary and evidence provenance.
type ReasonExplanation struct {
	RuleID   string           `json:"rule_id"`
	Summary  string           `json:"summary"`
	Evidence []EvidenceRecord `json:"evidence"`
}

// MissingEvidence documents evidence that was expected or requested but unavailable.
type MissingEvidence struct {
	Kind   string `json:"kind"`
	Source string `json:"source"`
	Reason string `json:"reason"`
}

// ChangeExplanation records differences observed relative to prior package releases.
type ChangeExplanation struct {
	Kind    string `json:"kind"`
	Summary string `json:"summary"`
}

// DecisionDocument is the stable compatibility surface representing a complete decision.
type DecisionDocument struct {
	SchemaVersion   string              `json:"schema_version"`
	DecisionID      string              `json:"decision_id"`
	Package         string              `json:"package"`
	Version         string              `json:"version"`
	Verdict         verdict.Kind        `json:"verdict"`
	Degraded        bool                `json:"degraded"`
	SnapshotID      string              `json:"snapshot_id"`
	Reasons         []ReasonExplanation `json:"reasons"`
	Changes         []ChangeExplanation `json:"changes"`
	MissingEvidence []MissingEvidence   `json:"missing_evidence"`
	NextCommand     string              `json:"next_command"`
}

// Option configures DecisionDocument assembly.
type Option func(*docConfig)

type docConfig struct {
	customID    string
	nextCommand string
	refTime     time.Time
}

// WithDecisionID overrides the default deterministic decision identifier.
func WithDecisionID(id string) Option {
	return func(c *docConfig) {
		c.customID = id
	}
}

// WithNextCommand overrides the automatically suggested next command.
func WithNextCommand(cmd string) Option {
	return func(c *docConfig) {
		c.nextCommand = cmd
	}
}

// WithReferenceTime provides a fixed clock reference for freshness evaluation.
func WithReferenceTime(t time.Time) Option {
	return func(c *docConfig) {
		c.refTime = t
	}
}

// ComputeDecisionID produces a stable, deterministic decision identifier.
func ComputeDecisionID(pkg, version, snapshotID string, v verdict.Kind) string {
	h := sha256.New()
	h.Write([]byte(pkg))
	h.Write([]byte(":"))
	h.Write([]byte(version))
	h.Write([]byte(":"))
	h.Write([]byte(snapshotID))
	h.Write([]byte(":"))
	h.Write([]byte(string(v)))
	sum := h.Sum(nil)
	return fmt.Sprintf("dec_%x", sum[:8])
}

// NewDecisionDocument constructs a DecisionDocument from an evaluated decision and snapshot.
func NewDecisionDocument(pkg, version string, dec verdict.Decision, snap evidence.Snapshot, opts ...Option) (*DecisionDocument, error) {
	if err := ValidateCoordinates(pkg, version); err != nil {
		return nil, err
	}

	cfg := &docConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	refTime := cfg.refTime
	if refTime.IsZero() {
		refTime = snap.CreatedAt()
	}
	if refTime.IsZero() {
		refTime = time.Now()
	}

	snapID := snap.ID()
	if snapID == "" {
		snapID = "sha256:empty"
	}

	decID := cfg.customID
	if decID == "" {
		decID = ComputeDecisionID(pkg, version, snapID, dec.Verdict)
	}

	degraded := dec.Degraded || snap.HasUnavailableEvidence()

	// Check observations for specific condition presence
	var hasMaliciousRecord bool
	var hasIntegrityMismatch bool
	var safeVersionSuggested string
	var confusableTarget string

	for _, obs := range snap.Observations() {
		if obs.Kind == evidence.KindMalicious && (obs.Observation == "malicious" || obs.Observation == "true") {
			hasMaliciousRecord = true
		}
		if obs.Kind == evidence.KindVulnerability && obs.Observation == "malicious" {
			hasMaliciousRecord = true
		}
		if obs.Kind == evidence.KindIntegrity && (obs.Observation == "mismatch" || obs.Observation == "failed") {
			hasIntegrityMismatch = true
		}
		if strings.HasPrefix(obs.Observation, "safe_version_suggested:") {
			safeVersionSuggested = strings.TrimPrefix(obs.Observation, "safe_version_suggested:")
		}
		if strings.HasPrefix(obs.Observation, "confusion_detected:") {
			confusableTarget = strings.TrimPrefix(obs.Observation, "confusion_detected:")
		} else if strings.HasPrefix(obs.Observation, "target:") {
			confusableTarget = strings.TrimPrefix(obs.Observation, "target:")
		}
	}

	reasons := make([]ReasonExplanation, 0, len(dec.Reasons))
	for _, r := range dec.Reasons {
		summary := r.Summary
		// Never describe a blocked package as malicious unless a malicious record actually exists.
		if r.RuleID == "core.integrity-or-malicious" {
			if hasIntegrityMismatch && !hasMaliciousRecord {
				summary = "package integrity verification failed (checksum mismatch)"
			} else if hasMaliciousRecord && !hasIntegrityMismatch {
				summary = "known malicious package record found in advisory database"
			} else if hasIntegrityMismatch && hasMaliciousRecord {
				summary = "package integrity verification failed and known malicious package record found"
			}
		}

		var evidenceRecords []EvidenceRecord
		seenSignals := make(map[string]bool)

		for _, kind := range r.SignalKinds {
			matching := snap.ObservationsByKind(kind)
			for _, obs := range matching {
				sigKey := fmt.Sprintf("%s:%s:%s", obs.Kind, obs.Source, obs.Observation)
				if seenSignals[sigKey] {
					continue
				}
				seenSignals[sigKey] = true

				freshness := classifyFreshness(obs, refTime)
				evidenceRecords = append(evidenceRecords, EvidenceRecord{
					Kind:          obs.Kind,
					Source:        SanitizeText(obs.Source),
					ObservedValue: SanitizeText(obs.Observation),
					Confidence:    obs.Confidence,
					RetrievedAt:   obs.RetrievedAt.UTC(),
					FreshUntil:    obs.FreshUntil.UTC(),
					Freshness:     freshness,
				})
			}
		}

		// Ensure evidence records are deterministically ordered
		sort.Slice(evidenceRecords, func(i, j int) bool {
			if evidenceRecords[i].Kind != evidenceRecords[j].Kind {
				return evidenceRecords[i].Kind < evidenceRecords[j].Kind
			}
			if evidenceRecords[i].Source != evidenceRecords[j].Source {
				return evidenceRecords[i].Source < evidenceRecords[j].Source
			}
			return evidenceRecords[i].ObservedValue < evidenceRecords[j].ObservedValue
		})

		reasons = append(reasons, ReasonExplanation{
			RuleID:   r.RuleID,
			Summary:  SanitizeText(summary),
			Evidence: evidenceRecords,
		})
	}

	// Missing evidence collection
	missing := collectMissingEvidence(snap)

	// Changes collection
	changes := collectChanges(snap)

	// Determine next command
	nextCmd := cfg.nextCommand
	if nextCmd == "" {
		nextCmd = determineNextCommand(pkg, version, dec.Verdict, decID, safeVersionSuggested, confusableTarget, hasIntegrityMismatch)
	}

	doc := &DecisionDocument{
		SchemaVersion:   CurrentSchemaVersion,
		DecisionID:      decID,
		Package:         SanitizeText(pkg),
		Version:         SanitizeText(version),
		Verdict:         dec.Verdict,
		Degraded:        degraded,
		SnapshotID:      snapID,
		Reasons:         reasons,
		Changes:         changes,
		MissingEvidence: missing,
		NextCommand:     SanitizeText(nextCmd),
	}

	return doc, nil
}

func classifyFreshness(obs verdict.Signal, refTime time.Time) string {
	if obs.Observation == "unavailable" {
		return "unavailable"
	}
	if obs.RetrievedAt.IsZero() {
		return "unknown"
	}
	if !obs.FreshUntil.IsZero() && refTime.After(obs.FreshUntil) {
		return "stale"
	}
	return "fresh"
}

func collectMissingEvidence(snap evidence.Snapshot) []MissingEvidence {
	var missing []MissingEvidence
	seen := make(map[string]bool)

	// Explicit unavailable observations
	for _, obs := range snap.Observations() {
		if obs.Observation == "unavailable" {
			source := obs.Source
			if source == "" {
				source = "provider"
			}
			key := obs.Kind + ":" + source
			if !seen[key] {
				seen[key] = true
				missing = append(missing, MissingEvidence{
					Kind:   obs.Kind,
					Source: source,
					Reason: "provider request failed or timed out",
				})
			}
		}
	}

	// Provider states
	for kind, state := range snap.ProviderStates() {
		if state == evidence.StateUnavailable {
			source := "provider"
			if obs, ok := snap.Observation(kind); ok && obs.Source != "" {
				source = obs.Source
			}
			key := kind + ":" + source
			if !seen[key] {
				seen[key] = true
				missing = append(missing, MissingEvidence{
					Kind:   kind,
					Source: source,
					Reason: "provider request failed or timed out",
				})
			}
		}
	}

	sort.Slice(missing, func(i, j int) bool {
		if missing[i].Kind != missing[j].Kind {
			return missing[i].Kind < missing[j].Kind
		}
		return missing[i].Source < missing[j].Source
	})

	if missing == nil {
		missing = []MissingEvidence{}
	}

	return missing
}

func collectChanges(snap evidence.Snapshot) []ChangeExplanation {
	var changes []ChangeExplanation

	for _, obs := range snap.Observations() {
		switch obs.Kind {
		case evidence.KindProvenance:
			if obs.Observation == "changed" || obs.Observation == "unexpected" {
				changes = append(changes, ChangeExplanation{
					Kind:    "provenance",
					Summary: "publisher or provenance changed from prior releases",
				})
			}
		case evidence.KindInstallScript:
			if obs.Observation == "script_added" {
				changes = append(changes, ChangeExplanation{
					Kind:    "install_script",
					Summary: "install script newly introduced in this version",
				})
			}
		case evidence.KindNameConfusion:
			if strings.HasPrefix(obs.Observation, "confusion_detected:") {
				target := strings.TrimPrefix(obs.Observation, "confusion_detected:")
				changes = append(changes, ChangeExplanation{
					Kind:    "name_confusion",
					Summary: fmt.Sprintf("package name confusable with target %q", target),
				})
			}
		}
	}

	if changes == nil {
		changes = []ChangeExplanation{}
	}

	return changes
}

func determineNextCommand(pkg, version string, v verdict.Kind, decisionID, safeVersion, confusableTarget string, integrityMismatch bool) string {
	switch v {
	case verdict.ApprovalRequired:
		return fmt.Sprintf("installgate approve %s", decisionID)
	case verdict.Block:
		if safeVersion != "" {
			return fmt.Sprintf("npm install %s@%s", pkg, safeVersion)
		}
		if confusableTarget != "" {
			return fmt.Sprintf("npm install %s", confusableTarget)
		}
		if integrityMismatch {
			return fmt.Sprintf("npm cache clean --force && npm install %s@%s", pkg, version)
		}
		return fmt.Sprintf("npm view %s versions", pkg)
	case verdict.Warn:
		return fmt.Sprintf("npm install %s@%s", pkg, version)
	case verdict.Allow:
		return fmt.Sprintf("npm install %s@%s", pkg, version)
	default:
		return fmt.Sprintf("npm view %s versions", pkg)
	}
}
