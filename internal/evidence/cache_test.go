package evidence

import (
	"errors"
	"testing"
	"time"

	"github.com/aniklavida/installgate/internal/verdict"
)

func TestCacheEvidenceFreshnessTransitions(t *testing.T) {
	c := NewMemoryCache()
	baseTime := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	freshUntil := baseTime.Add(1 * time.Hour)
	staleUntil := baseTime.Add(24 * time.Hour)

	sig := verdict.Signal{
		Kind:        KindVulnerability,
		Source:      "osv",
		Observation: "none",
		Confidence:  ConfidenceHigh,
		RetrievedAt: baseTime,
		FreshUntil:  freshUntil,
	}
	outcome := NewAvailableOutcome(KindVulnerability, "osv", []verdict.Signal{sig}, baseTime, freshUntil)

	c.Put("pkg-a", "1.0.0", outcome, staleUntil)

	// 1. Check at +30m: Fresh hit -> Available
	t30m := baseTime.Add(30 * time.Minute)
	got, ok := c.Get(KindVulnerability, "pkg-a", "1.0.0", t30m)
	if !ok {
		t.Fatal("expected cache hit at +30m")
	}
	if got.State() != StateAvailable {
		t.Fatalf("expected StateAvailable at +30m, got %v", got.State())
	}

	// 2. Check at +2h: Stale hit -> Stale
	t2h := baseTime.Add(2 * time.Hour)
	gotStale, ok := c.Get(KindVulnerability, "pkg-a", "1.0.0", t2h)
	if !ok {
		t.Fatal("expected cache hit at +2h")
	}
	if gotStale.State() != StateStale {
		t.Fatalf("expected StateStale at +2h, got %v", gotStale.State())
	}
	if gotStale.Reason() == "" {
		t.Fatal("stale outcome must include rationale")
	}

	// 3. Check at +25h: Expired -> cache miss
	t25h := baseTime.Add(25 * time.Hour)
	_, ok = c.Get(KindVulnerability, "pkg-a", "1.0.0", t25h)
	if ok {
		t.Fatal("expected cache miss at +25h (past stale tolerance)")
	}
}

func TestCacheRejectsUnavailableOutcomes(t *testing.T) {
	c := NewMemoryCache()
	baseTime := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	unavail := NewUnavailableOutcome(KindVulnerability, "osv", errors.New("network timeout"), baseTime)

	c.Put("pkg-b", "1.0.0", unavail, baseTime.Add(24*time.Hour))

	_, ok := c.Get(KindVulnerability, "pkg-b", "1.0.0", baseTime)
	if ok {
		t.Fatal("cache must never store or serve unavailable outcomes")
	}
}

func TestCachedAllowDistinguishesFreshFromStale(t *testing.T) {
	c := NewMemoryCache()
	baseTime := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	freshUntil := baseTime.Add(30 * time.Minute)
	staleUntil := baseTime.Add(6 * time.Hour)

	allowDecision := verdict.Decision{
		Verdict: verdict.Allow,
		Reasons: []verdict.Reason{{RuleID: "core.policy-satisfied", Summary: "satisfied"}},
	}

	c.PutCachedAllow("pkg-c", "1.0.0", allowDecision, "sha256:dummy", baseTime, freshUntil, staleUntil)

	// Within fresh window (at +10m)
	t10m := baseTime.Add(10 * time.Minute)
	cached, ok := c.GetCachedAllow("pkg-c", "1.0.0", t10m)
	if !ok {
		t.Fatal("expected cached allow at +10m")
	}
	if !cached.IsFresh(t10m) {
		t.Fatal("cached allow at +10m must be fresh")
	}
	if cached.IsStale(t10m) {
		t.Fatal("cached allow at +10m must not be stale")
	}

	// Past fresh window, within stale tolerance (at +2h)
	t2h := baseTime.Add(2 * time.Hour)
	cached2, ok := c.GetCachedAllow("pkg-c", "1.0.0", t2h)
	if !ok {
		t.Fatal("expected cached allow at +2h")
	}
	if cached2.IsFresh(t2h) {
		t.Fatal("cached allow at +2h must not be fresh")
	}
	if !cached2.IsStale(t2h) {
		t.Fatal("cached allow at +2h must be stale-but-usable")
	}

	// Past stale tolerance (at +7h)
	t7h := baseTime.Add(7 * time.Hour)
	_, ok = c.GetCachedAllow("pkg-c", "1.0.0", t7h)
	if ok {
		t.Fatal("cached allow at +7h must be expired and not returned")
	}
}
