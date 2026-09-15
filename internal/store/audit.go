package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/aniklavida/installgate/internal/evidence"
	"github.com/aniklavida/installgate/internal/explanation"
	"github.com/aniklavida/installgate/internal/verdict"
)

// ExportAuditJSON exports all audit events in forward chronological order as a JSON array,
// ensuring that all credentials, authorization headers, and secrets are scrubbed.
func ExportAuditJSON(ctx context.Context, s Store, w io.Writer) error {
	if s == nil {
		return errors.New("store cannot be nil")
	}
	if w == nil {
		return errors.New("writer cannot be nil")
	}

	const batchSize = 250
	offset := 0

	if _, err := io.WriteString(w, "[\n"); err != nil {
		return err
	}

	first := true
	for {
		events, err := s.ListAuditEvents(ctx, batchSize, offset)
		if err != nil {
			return fmt.Errorf("failed listing audit events for export: %w", err)
		}
		if len(events) == 0 {
			break
		}

		for _, ev := range events {
			sanitizedEv := sanitizeAuditEventForExport(ev)
			data, err := json.MarshalIndent(sanitizedEv, "  ", "  ")
			if err != nil {
				return fmt.Errorf("failed marshaling sanitized audit event: %w", err)
			}

			if !first {
				if _, err := io.WriteString(w, ",\n"); err != nil {
					return err
				}
			}
			first = false

			if _, err := io.WriteString(w, "  "); err != nil {
				return err
			}
			if _, err := w.Write(data); err != nil {
				return err
			}
		}

		offset += len(events)
		if len(events) < batchSize {
			break
		}
	}

	if _, err := io.WriteString(w, "\n]\n"); err != nil {
		return err
	}

	return nil
}

func sanitizeAuditEventForExport(ev *AuditEvent) *AuditEvent {
	if ev == nil {
		return nil
	}
	clone := *ev
	if clone.Metadata != nil {
		clone.Metadata = sanitizeMetadata(clone.Metadata)
	}
	// Package contents/bytes are never stored, but verify text fields
	clone.Actor = RedactSensitiveString(clone.Actor)
	return &clone
}

// ReconstructDecisionFromAudit reconstructs the decision document, rule, and evidence snapshot
// directly from an audit event.
func ReconstructDecisionFromAudit(ev *AuditEvent) (*explanation.DecisionDocument, *evidence.Snapshot, error) {
	if ev == nil {
		return nil, nil, errors.New("audit event cannot be nil")
	}
	if ev.EventType != "decision" {
		return nil, nil, fmt.Errorf("event type %q is not a decision event", ev.EventType)
	}

	snap := ev.Snapshot
	if snap == nil {
		return nil, nil, errors.New("audit event does not contain an evidence snapshot")
	}

	reasons := []explanation.ReasonExplanation{
		{
			RuleID:  ev.RuleID,
			Summary: fmt.Sprintf("verdict %s determined by rule %s", ev.Verdict, ev.RuleID),
		},
	}

	doc := &explanation.DecisionDocument{
		SchemaVersion: explanation.CurrentSchemaVersion,
		DecisionID:    ev.DecisionID,
		Package:       ev.Package,
		Version:       ev.Version,
		Verdict:       verdict.Kind(ev.Verdict),
		SnapshotID:    snap.ID(),
		Reasons:       reasons,
	}

	return doc, snap, nil
}
