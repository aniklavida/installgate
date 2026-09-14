package explanation

import (
	"strings"
	"testing"
	"time"

	"github.com/aniklavida/installgate/internal/evidence"
	"github.com/aniklavida/installgate/internal/policy"
	"github.com/aniklavida/installgate/internal/verdict"
)

func fixedTime() time.Time {
	return time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
}

func TestExplanation_VulnerabilityBlock(t *testing.T) {
	now := fixedTime()
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
	snap := evidence.NewSnapshot("lodash", "4.17.20", signals, states, now)

	pol := policy.NewDefaultPolicy()
	dec := pol.EvaluateSnapshot(snap)

	doc, err := NewDecisionDocument("lodash", "4.17.20", dec, snap, WithReferenceTime(now))
	if err != nil {
		t.Fatalf("unexpected error creating document: %v", err)
	}

	if doc.Verdict != verdict.Block {
		t.Errorf("verdict = %q, want %q", doc.Verdict, verdict.Block)
	}
	if doc.Degraded {
		t.Errorf("degraded should be false")
	}
	if len(doc.Reasons) != 1 {
		t.Fatalf("reasons count = %d, want 1", len(doc.Reasons))
	}
	if doc.Reasons[0].RuleID != "core.vulnerability-threshold" {
		t.Errorf("rule_id = %q, want core.vulnerability-threshold", doc.Reasons[0].RuleID)
	}
	if len(doc.Reasons[0].Evidence) != 1 {
		t.Fatalf("evidence count = %d, want 1", len(doc.Reasons[0].Evidence))
	}

	ev := doc.Reasons[0].Evidence[0]
	if ev.Source != "osv" || ev.Kind != "vulnerability" || ev.ObservedValue != "critical" {
		t.Errorf("unexpected evidence record: %+v", ev)
	}
	if ev.Freshness != "fresh" {
		t.Errorf("freshness = %q, want fresh", ev.Freshness)
	}

	// Human rendering
	human := RenderHuman(doc)
	lines := strings.Split(strings.TrimSpace(human), "\n")
	if !strings.HasPrefix(lines[0], "InstallGate Decision: BLOCKED") {
		t.Errorf("line 1 = %q, want prefix 'InstallGate Decision: BLOCKED'", lines[0])
	}
	if !strings.Contains(human, "core.vulnerability-threshold") {
		t.Errorf("human output must name rule identifier core.vulnerability-threshold")
	}
	if !strings.Contains(human, "Source:     osv") {
		t.Errorf("human output must name evidence source osv")
	}
	if !strings.Contains(human, "npm view lodash versions") {
		t.Errorf("human output must suggest next command")
	}
	if !strings.Contains(human, "MISSING EVIDENCE:\n  none (complete evaluation)") {
		t.Errorf("human output must prominently announce missing evidence status")
	}

	// JSON rendering
	jsonData, err := RenderJSON(doc)
	if err != nil {
		t.Fatalf("RenderJSON error: %v", err)
	}
	parsed, err := ParseJSON(jsonData)
	if err != nil {
		t.Fatalf("ParseJSON error: %v", err)
	}
	if parsed.DecisionID != doc.DecisionID {
		t.Errorf("parsed ID = %q, want %q", parsed.DecisionID, doc.DecisionID)
	}
}

func TestExplanation_IntegrityMismatch_NeverMentionsMalicious(t *testing.T) {
	now := fixedTime()
	signals := []verdict.Signal{
		{
			Kind:        evidence.KindIntegrity,
			Source:      "npm_registry",
			Observation: "mismatch",
			Confidence:  evidence.ConfidenceHigh,
			RetrievedAt: now,
			FreshUntil:  now.Add(24 * time.Hour),
		},
	}
	states := map[string]evidence.State{
		evidence.KindIntegrity: evidence.StateAvailable,
	}
	snap := evidence.NewSnapshot("safe-pkg", "1.0.0", signals, states, now)

	pol := policy.NewDefaultPolicy()
	dec := pol.EvaluateSnapshot(snap)

	doc, err := NewDecisionDocument("safe-pkg", "1.0.0", dec, snap, WithReferenceTime(now))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	human := RenderHuman(doc)
	// Hard constraint: A blocked package is described by what the evidence showed, NEVER as 'malicious' unless a malicious record actually exists.
	if strings.Contains(strings.ToLower(doc.Reasons[0].Summary), "malicious") {
		t.Fatalf("integrity mismatch summary must NEVER be described as malicious: %s", doc.Reasons[0].Summary)
	}
	for _, line := range strings.Split(human, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "Summary:") && strings.Contains(strings.ToLower(line), "malicious") {
			t.Fatalf("summary line describes package as malicious: %s", line)
		}
	}
	if !strings.Contains(human, "checksum mismatch") {
		t.Errorf("expected checksum mismatch description in human output: %s", human)
	}

	jsonData, err := RenderJSON(doc)
	if err != nil {
		t.Fatalf("RenderJSON error: %v", err)
	}
	parsed, err := ParseJSON(jsonData)
	if err != nil {
		t.Fatalf("ParseJSON error: %v", err)
	}
	if strings.Contains(strings.ToLower(parsed.Reasons[0].Summary), "malicious") {
		t.Fatalf("JSON reason summary must NEVER contain 'malicious': %s", parsed.Reasons[0].Summary)
	}
}

func TestExplanation_DegradedAnnouncementInFirstLine(t *testing.T) {
	now := fixedTime()
	signals := []verdict.Signal{
		{
			Kind:        evidence.KindAvailability,
			Source:      "osv",
			Observation: "unavailable",
			Confidence:  evidence.ConfidenceNone,
			RetrievedAt: now,
			FreshUntil:  now,
		},
	}
	states := map[string]evidence.State{
		evidence.KindAvailability: evidence.StateUnavailable,
	}
	snap := evidence.NewSnapshot("pkg-x", "2.0.0", signals, states, now)

	pol := policy.NewDefaultPolicy()
	dec := pol.EvaluateSnapshot(snap)

	doc, err := NewDecisionDocument("pkg-x", "2.0.0", dec, snap, WithReferenceTime(now))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !doc.Degraded {
		t.Fatalf("expected degraded decision")
	}

	human := RenderHuman(doc)
	lines := strings.Split(strings.TrimSpace(human), "\n")
	// Hard constraint: A degraded decision announces that in the FIRST LINE of the human rendering.
	if !strings.HasPrefix(lines[0], "DEGRADED DECISION:") {
		t.Fatalf("expected first line to announce DEGRADED DECISION, got: %q", lines[0])
	}
	if !strings.Contains(human, "MISSING EVIDENCE:\n  - Kind:   availability") {
		t.Errorf("expected missing evidence section in degraded output: %s", human)
	}
}

func TestExplanation_NameConfusionApprovalRequired(t *testing.T) {
	now := fixedTime()
	signals := []verdict.Signal{
		{
			Kind:        evidence.KindNameConfusion,
			Source:      "local_similarity",
			Observation: "confusion_detected:react",
			Confidence:  evidence.ConfidenceHigh,
			RetrievedAt: now,
			FreshUntil:  now.Add(12 * time.Hour),
		},
		{
			Kind:        evidence.KindPackageAge,
			Source:      "npm_registry",
			Observation: "fresh",
			Confidence:  evidence.ConfidenceHigh,
			RetrievedAt: now,
			FreshUntil:  now.Add(1 * time.Hour),
		},
	}
	states := map[string]evidence.State{
		evidence.KindNameConfusion: evidence.StateAvailable,
		evidence.KindPackageAge:    evidence.StateAvailable,
	}
	snap := evidence.NewSnapshot("re-act", "0.0.1", signals, states, now)

	pol := policy.NewDefaultPolicy()
	dec := pol.EvaluateSnapshot(snap)

	doc, err := NewDecisionDocument("re-act", "0.0.1", dec, snap, WithReferenceTime(now))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if doc.Verdict != verdict.ApprovalRequired {
		t.Fatalf("verdict = %q, want %q", doc.Verdict, verdict.ApprovalRequired)
	}
	if !strings.Contains(doc.NextCommand, "installgate approve") {
		t.Errorf("expected approve next command, got: %s", doc.NextCommand)
	}
	if len(doc.Changes) == 0 || !strings.Contains(doc.Changes[0].Summary, "react") {
		t.Errorf("expected name confusion in changes, got: %+v", doc.Changes)
	}

	human := RenderHuman(doc)
	if !strings.Contains(human, "InstallGate Decision: APPROVAL REQUIRED") {
		t.Errorf("human output missing approval required: %s", human)
	}
	if !strings.Contains(human, "installgate approve "+doc.DecisionID) {
		t.Errorf("human output missing exact approve command: %s", human)
	}
}

func TestExplanation_SafeVersionSuggestionNextCommand(t *testing.T) {
	now := fixedTime()
	signals := []verdict.Signal{
		{
			Kind:        evidence.KindVulnerability,
			Source:      "osv",
			Observation: "critical",
			Confidence:  evidence.ConfidenceHigh,
			RetrievedAt: now,
			FreshUntil:  now.Add(1 * time.Hour),
		},
		{
			Kind:        evidence.KindVulnerability,
			Source:      "osv",
			Observation: "safe_version_suggested:4.18.3",
			Confidence:  evidence.ConfidenceHigh,
			RetrievedAt: now,
			FreshUntil:  now.Add(1 * time.Hour),
		},
	}
	states := map[string]evidence.State{
		evidence.KindVulnerability: evidence.StateAvailable,
	}
	snap := evidence.NewSnapshot("express", "4.18.2", signals, states, now)

	pol := policy.NewDefaultPolicy()
	dec := pol.EvaluateSnapshot(snap)

	doc, err := NewDecisionDocument("express", "4.18.2", dec, snap, WithReferenceTime(now))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if doc.NextCommand != "npm install express@4.18.3" {
		t.Errorf("expected next command 'npm install express@4.18.3', got %q", doc.NextCommand)
	}
}
