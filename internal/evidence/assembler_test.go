package evidence

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aniklavida/installgate/internal/verdict"
)

type mockProvider struct {
	name      string
	kind      string
	calls     int
	onProvide func(ctx context.Context, q Query) Outcome
}

func (m *mockProvider) Name() string { return m.name }
func (m *mockProvider) Kind() string { return m.kind }
func (m *mockProvider) Provide(ctx context.Context, q Query) Outcome {
	m.calls++
	if m.onProvide != nil {
		return m.onProvide(ctx, q)
	}
	return NewUnavailableOutcome(m.kind, m.name, errors.New("not implemented"), time.Now())
}

func TestAssemblerFreshAssemblyAndCacheHit(t *testing.T) {
	baseTime := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	currTime := baseTime

	p := &mockProvider{
		name: "mock-integrity",
		kind: KindIntegrity,
		onProvide: func(ctx context.Context, q Query) Outcome {
			return NewAvailableOutcome(KindIntegrity, "mock-integrity", []verdict.Signal{
				{
					Kind:        KindIntegrity,
					Source:      "mock-integrity",
					Observation: "sha512-valid",
					Confidence:  ConfidenceHigh,
					RetrievedAt: currTime,
					FreshUntil:  currTime.Add(24 * time.Hour),
				},
			}, currTime, currTime.Add(24*time.Hour))
		},
	}

	cache := NewMemoryCache()
	assembler := NewAssembler(
		WithClock(func() time.Time { return currTime }),
		WithProviders(p),
		WithCache(cache),
	)

	// First call: provider is invoked
	snap1, err := assembler.Assemble(context.Background(), "react", "18.2.0")
	if err != nil {
		t.Fatalf("first assemble failed: %v", err)
	}
	if p.calls != 1 {
		t.Fatalf("expected 1 provider call, got %d", p.calls)
	}
	if snap1.ID() == "" {
		t.Fatal("expected non-empty snapshot ID")
	}

	// Advance clock by 10 minutes (well within 24h fresh TTL)
	currTime = currTime.Add(10 * time.Minute)

	// Second call: served from cache; provider not invoked again
	snap2, err := assembler.Assemble(context.Background(), "react", "18.2.0")
	if err != nil {
		t.Fatalf("second assemble failed: %v", err)
	}
	if p.calls != 1 {
		t.Fatalf("expected cache hit with 1 provider call, got %d", p.calls)
	}
	// Identical observations produced from cache yield the identical snapshot identity
	if snap1.ID() != snap2.ID() {
		t.Fatalf("cached snapshot ID mismatch: snap1=%s, snap2=%s", snap1.ID(), snap2.ID())
	}
}

func TestAssemblerOutageWithoutCache(t *testing.T) {
	baseTime := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)

	p := &mockProvider{
		name: "failing-vuln-provider",
		kind: KindVulnerability,
		onProvide: func(ctx context.Context, q Query) Outcome {
			return NewUnavailableOutcome(KindVulnerability, "failing-vuln-provider", errors.New("upstream outage"), baseTime)
		},
	}

	assembler := NewAssembler(
		WithClock(func() time.Time { return baseTime }),
		WithProviders(p),
	)

	snap, err := assembler.Assemble(context.Background(), "pkg", "1.0.0")
	if err != nil {
		t.Fatalf("assemble failed: %v", err)
	}

	if !snap.HasUnavailableEvidence() {
		t.Fatal("snapshot must indicate unavailable evidence")
	}
	if snap.State(KindVulnerability) != StateUnavailable {
		t.Fatalf("state for vulnerability must be StateUnavailable, got %v", snap.State(KindVulnerability))
	}
	obs, ok := snap.Observation(KindVulnerability)
	if !ok {
		t.Fatal("snapshot must contain an explicit observation for the unavailable kind")
	}
	if obs.Observation != "unavailable" {
		t.Fatalf("observation must be 'unavailable', got %q", obs.Observation)
	}
}

func TestAssemblerOutageWithStaleCacheFallback(t *testing.T) {
	baseTime := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	currTime := baseTime

	p := &mockProvider{
		name: "vuln-provider",
		kind: KindVulnerability,
		onProvide: func(ctx context.Context, q Query) Outcome {
			return NewAvailableOutcome(KindVulnerability, "vuln-provider", []verdict.Signal{
				{
					Kind:        KindVulnerability,
					Source:      "vuln-provider",
					Observation: "none",
					Confidence:  ConfidenceHigh,
					RetrievedAt: currTime,
					FreshUntil:  currTime.Add(1 * time.Hour),
				},
			}, currTime, currTime.Add(1*time.Hour))
		},
	}

	cache := NewMemoryCache()
	assembler := NewAssembler(
		WithClock(func() time.Time { return currTime }),
		WithProviders(p),
		WithCache(cache),
	)

	// Step 1: Prime cache
	_, err := assembler.Assemble(context.Background(), "pkg", "1.0.0")
	if err != nil {
		t.Fatalf("assemble 1 failed: %v", err)
	}

	// Step 2: Advance time so cache entry becomes stale (at +2h, fresh is 1h, stale tolerance is 24h)
	currTime = currTime.Add(2 * time.Hour)

	// Step 3: Upstream has an outage
	p.onProvide = func(ctx context.Context, q Query) Outcome {
		return NewUnavailableOutcome(KindVulnerability, "vuln-provider", errors.New("upstream down"), currTime)
	}

	// Step 4: Assemble during outage -> falls back to stale cache
	snap, err := assembler.Assemble(context.Background(), "pkg", "1.0.0")
	if err != nil {
		t.Fatalf("assemble 2 failed: %v", err)
	}

	if snap.State(KindVulnerability) != StateStale {
		t.Fatalf("expected StateStale fallback, got %v", snap.State(KindVulnerability))
	}
}

func TestAssemblerCachedAllowPresence(t *testing.T) {
	baseTime := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	currTime := baseTime

	cache := NewMemoryCache()
	allowDecision := verdict.Decision{
		Verdict: verdict.Allow,
		Reasons: []verdict.Reason{{RuleID: "core.policy-satisfied"}},
	}
	cache.PutCachedAllow("pkg", "1.0.0", allowDecision, "sha256:orig", baseTime, baseTime.Add(30*time.Minute), baseTime.Add(6*time.Hour))

	assembler := NewAssembler(
		WithClock(func() time.Time { return currTime }),
		WithCache(cache),
	)

	// Within 30 minutes: fresh allow
	snapFresh, err := assembler.Assemble(context.Background(), "pkg", "1.0.0")
	if err != nil {
		t.Fatalf("assemble failed: %v", err)
	}
	cacheSig, ok := snapFresh.Observation(KindCache)
	if !ok || cacheSig.Observation != "fresh_allow" {
		t.Fatalf("expected fresh_allow observation, got: %+v", cacheSig)
	}

	// Advance to +2 hours: stale allow
	currTime = currTime.Add(2 * time.Hour)
	snapStale, err := assembler.Assemble(context.Background(), "pkg", "1.0.0")
	if err != nil {
		t.Fatalf("assemble failed: %v", err)
	}
	cacheSigStale, ok := snapStale.Observation(KindCache)
	if !ok || cacheSigStale.Observation != "stale_allow" {
		t.Fatalf("expected stale_allow observation, got: %+v", cacheSigStale)
	}
}
