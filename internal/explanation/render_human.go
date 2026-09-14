package explanation

import (
	"fmt"
	"strings"
	"time"

	"github.com/aniklavida/installgate/internal/verdict"
)

// RenderHuman produces a clear, deterministic human terminal rendering of a DecisionDocument.
func RenderHuman(doc *DecisionDocument) string {
	if doc == nil {
		return ""
	}

	var sb strings.Builder

	// Hard constraint: A degraded decision announces that in the FIRST LINE of the human rendering.
	if doc.Degraded {
		sb.WriteString("DEGRADED DECISION: live evidence unavailable; evaluation completed with fallback policy.\n\n")
		sb.WriteString(fmt.Sprintf("InstallGate Decision: %s\n", humanVerdict(doc.Verdict)))
	} else {
		sb.WriteString(fmt.Sprintf("InstallGate Decision: %s\n", humanVerdict(doc.Verdict)))
	}

	sb.WriteString(fmt.Sprintf("Decision ID: %s\n", doc.DecisionID))
	sb.WriteString(fmt.Sprintf("Package:     %s@%s\n", doc.Package, doc.Version))
	sb.WriteString(fmt.Sprintf("Snapshot:    %s\n\n", doc.SnapshotID))

	// Evidence section
	sectionTitle := "HOLD EVIDENCE:"
	if doc.Verdict == verdict.Allow {
		sectionTitle = "POLICY EVALUATION:"
	} else if doc.Verdict == verdict.Warn {
		sectionTitle = "WARNING EVIDENCE:"
	}
	sb.WriteString(sectionTitle + "\n")

	hasOSV := false
	if len(doc.Reasons) == 0 {
		sb.WriteString("  none recorded\n\n")
	} else {
		for _, r := range doc.Reasons {
			sb.WriteString(fmt.Sprintf("  Rule:    %s\n", r.RuleID))
			sb.WriteString(fmt.Sprintf("  Summary: %s\n", r.Summary))
			sb.WriteString("  Evidence:\n")
			if len(r.Evidence) == 0 {
				sb.WriteString("    none recorded\n")
			} else {
				for _, ev := range r.Evidence {
					if strings.EqualFold(ev.Source, "osv") {
						hasOSV = true
					}
					sb.WriteString(fmt.Sprintf("    - Kind:       %s\n", ev.Kind))
					sb.WriteString(fmt.Sprintf("      Source:     %s\n", ev.Source))
					sb.WriteString(fmt.Sprintf("      Observed:   %s\n", ev.ObservedValue))
					sb.WriteString(fmt.Sprintf("      Confidence: %s\n", ev.Confidence))

					freshnessStr := ev.Freshness
					if !ev.RetrievedAt.IsZero() {
						freshnessStr += fmt.Sprintf(" (retrieved %s", ev.RetrievedAt.Format(time.RFC3339))
						if !ev.FreshUntil.IsZero() {
							freshnessStr += fmt.Sprintf(", fresh until %s", ev.FreshUntil.Format(time.RFC3339))
						}
						freshnessStr += ")"
					}
					sb.WriteString(fmt.Sprintf("      Freshness:  %s\n", freshnessStr))
				}
			}
		}
		sb.WriteString("\n")
	}

	// Missing evidence section
	sb.WriteString("MISSING EVIDENCE:\n")
	if len(doc.MissingEvidence) == 0 {
		sb.WriteString("  none (complete evaluation)\n\n")
	} else {
		for _, m := range doc.MissingEvidence {
			sb.WriteString(fmt.Sprintf("  - Kind:   %s\n", m.Kind))
			sb.WriteString(fmt.Sprintf("    Source: %s\n", m.Source))
			sb.WriteString(fmt.Sprintf("    Reason: %s\n", m.Reason))
		}
		sb.WriteString("\n")
	}

	// Changes section
	sb.WriteString("CHANGES DETECTED:\n")
	if len(doc.Changes) == 0 {
		sb.WriteString("  none (no unexpected changes observed)\n\n")
	} else {
		for _, ch := range doc.Changes {
			sb.WriteString(fmt.Sprintf("  - %s: %s\n", ch.Kind, ch.Summary))
		}
		sb.WriteString("\n")
	}

	// Next command section
	sb.WriteString("NEXT COMMAND:\n")
	if doc.NextCommand != "" {
		sb.WriteString(fmt.Sprintf("  %s\n", doc.NextCommand))
	} else {
		sb.WriteString("  installgate explain " + doc.DecisionID + "\n")
	}

	if hasOSV {
		sb.WriteString("\nNOTE: Advisory evidence sourced from OSV (GitHub Advisory Database).\n")
	}

	return sb.String()
}

func humanVerdict(v verdict.Kind) string {
	switch v {
	case verdict.Allow:
		return "ALLOWED"
	case verdict.Warn:
		return "WARNING"
	case verdict.ApprovalRequired:
		return "APPROVAL REQUIRED"
	case verdict.Block:
		return "BLOCKED"
	default:
		return strings.ToUpper(string(v))
	}
}
