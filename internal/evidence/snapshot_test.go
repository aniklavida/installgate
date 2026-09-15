package evidence

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aniklavida/installgate/internal/verdict"
)

func TestSnapshotStableIdentityOrderIndependence(t *testing.T) {
	baseTime := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)

	sigA := verdict.Signal{
		Kind:        KindVulnerability,
		Source:      "osv",
		Observation: "none",
		Confidence:  ConfidenceHigh,
		RetrievedAt: baseTime,
		FreshUntil:  baseTime.Add(1 * time.Hour),
	}
	sigB := verdict.Signal{
		Kind:        KindIntegrity,
		Source:      "npm",
		Observation: "sha512-expected",
		Confidence:  ConfidenceHigh,
		RetrievedAt: baseTime,
		FreshUntil:  baseTime.Add(24 * time.Hour),
	}
	sigC := verdict.Signal{
		Kind:        KindPublishHistory,
		Source:      "npm",
		Observation: "published-2-years-ago",
		Confidence:  ConfidenceHigh,
		RetrievedAt: baseTime,
		FreshUntil:  baseTime.Add(15 * time.Minute),
	}

	states := map[string]State{
		KindVulnerability:  StateAvailable,
		KindIntegrity:      StateAvailable,
		KindPublishHistory: StateAvailable,
	}

	// Create snapshot with order A, B, C
	snap1 := NewSnapshot("left-pad", "1.3.0", []verdict.Signal{sigA, sigB, sigC}, states, baseTime)

	// Create snapshot with reverse order C, B, A
	snap2 := NewSnapshot("left-pad", "1.3.0", []verdict.Signal{sigC, sigB, sigA}, states, baseTime)

	// Create snapshot with shuffled order B, A, C
	snap3 := NewSnapshot("left-pad", "1.3.0", []verdict.Signal{sigB, sigA, sigC}, states, baseTime)

	if snap1.ID() == "" {
		t.Fatal("snapshot ID must not be empty")
	}
	if !strings.HasPrefix(snap1.ID(), "sha256:") {
		t.Fatalf("snapshot ID must have sha256: prefix, got %q", snap1.ID())
	}
	if snap1.ID() != snap2.ID() {
		t.Fatalf("snapshot ID must be order-independent: snap1=%s, snap2=%s", snap1.ID(), snap2.ID())
	}
	if snap1.ID() != snap3.ID() {
		t.Fatalf("snapshot ID must be order-independent: snap1=%s, snap3=%s", snap1.ID(), snap3.ID())
	}
}

func TestSnapshotIdentityChangesOnObservationDiff(t *testing.T) {
	baseTime := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)

	sig1 := verdict.Signal{
		Kind:        KindVulnerability,
		Source:      "osv",
		Observation: "none",
		Confidence:  ConfidenceHigh,
		RetrievedAt: baseTime,
		FreshUntil:  baseTime.Add(1 * time.Hour),
	}
	sig2 := verdict.Signal{
		Kind:        KindVulnerability,
		Source:      "osv",
		Observation: "above_threshold",
		Confidence:  ConfidenceHigh,
		RetrievedAt: baseTime,
		FreshUntil:  baseTime.Add(1 * time.Hour),
	}

	snapClean := NewSnapshot("pkg-a", "1.0.0", []verdict.Signal{sig1}, nil, baseTime)
	snapVuln := NewSnapshot("pkg-a", "1.0.0", []verdict.Signal{sig2}, nil, baseTime)

	if snapClean.ID() == snapVuln.ID() {
		t.Fatal("snapshots with differing observations must produce distinct IDs")
	}
}

func TestSnapshotJSONSerializationRoundTrip(t *testing.T) {
	baseTime := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)

	signals := []verdict.Signal{
		{
			Kind:        KindVulnerability,
			Source:      "osv",
			Observation: "none",
			Confidence:  ConfidenceHigh,
			RetrievedAt: baseTime,
			FreshUntil:  baseTime.Add(1 * time.Hour),
		},
		{
			Kind:        KindIntegrity,
			Source:      "npm",
			Observation: "sha512-abc",
			Confidence:  ConfidenceHigh,
			RetrievedAt: baseTime,
			FreshUntil:  baseTime.Add(24 * time.Hour),
		},
	}
	states := map[string]State{
		KindVulnerability: StateAvailable,
		KindIntegrity:     StateAvailable,
	}

	original := NewSnapshot("test-pkg", "2.0.0", signals, states, baseTime)

	// Serialize
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal snapshot: %v", err)
	}

	// Deserialize
	var restored Snapshot
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("failed to unmarshal snapshot: %v", err)
	}

	if restored.ID() != original.ID() {
		t.Fatalf("restored ID %q does not match original ID %q", restored.ID(), original.ID())
	}
	if restored.Package() != original.Package() {
		t.Fatalf("package %q != %q", restored.Package(), original.Package())
	}
	if restored.Version() != original.Version() {
		t.Fatalf("version %q != %q", restored.Version(), original.Version())
	}
	if len(restored.Observations()) != len(original.Observations()) {
		t.Fatalf("observation count mismatch: %d != %d", len(restored.Observations()), len(original.Observations()))
	}
	for i := range restored.Observations() {
		if restored.Observations()[i] != original.Observations()[i] {
			t.Fatalf("observation %d mismatch: got %+v, want %+v", i, restored.Observations()[i], original.Observations()[i])
		}
	}
}

func TestSnapshotTamperDetection(t *testing.T) {
	baseTime := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	sig := verdict.Signal{
		Kind:        KindVulnerability,
		Source:      "osv",
		Observation: "none",
		Confidence:  ConfidenceHigh,
		RetrievedAt: baseTime,
		FreshUntil:  baseTime.Add(1 * time.Hour),
	}
	snap := NewSnapshot("pkg", "1.0.0", []verdict.Signal{sig}, nil, baseTime)

	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	// Tamper with the observation in JSON: change "none" to "above_threshold"
	tamperedJSON := strings.Replace(string(data), `"observation":"none"`, `"observation":"above_threshold"`, 1)

	var tampered Snapshot
	err = json.Unmarshal([]byte(tamperedJSON), &tampered)
	if err == nil {
		t.Fatal("unmarshaling tampered snapshot payload must fail with identity mismatch")
	}
	if !strings.Contains(err.Error(), "identity mismatch") {
		t.Fatalf("expected identity mismatch error, got: %v", err)
	}
}

func TestSnapshotImmutability(t *testing.T) {
	baseTime := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	sig := verdict.Signal{
		Kind:        KindVulnerability,
		Source:      "osv",
		Observation: "none",
		Confidence:  ConfidenceHigh,
		RetrievedAt: baseTime,
		FreshUntil:  baseTime.Add(1 * time.Hour),
	}

	snap := NewSnapshot("pkg", "1.0.0", []verdict.Signal{sig}, map[string]State{"vulnerability": StateAvailable}, baseTime)

	// Mutating the returned slice must not change internal snapshot state
	obs := snap.Observations()
	obs[0].Observation = "tampered"

	if snap.Observations()[0].Observation == "tampered" {
		t.Fatal("mutating Observations() return value must not affect internal state")
	}

	// Mutating the returned map must not change internal snapshot state
	states := snap.ProviderStates()
	states["vulnerability"] = StateUnavailable

	if snap.ProviderStates()["vulnerability"] == StateUnavailable {
		t.Fatal("mutating ProviderStates() return value must not affect internal state")
	}
}
