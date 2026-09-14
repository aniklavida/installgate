package evidence

import (
	"sync"
	"time"

	"github.com/aniklavida/installgate/internal/verdict"
)

// CachedAllow stores an allow decision with its fresh and stale retention boundaries.
type CachedAllow struct {
	Decision    verdict.Decision `json:"decision"`
	SnapshotID  string           `json:"snapshot_id"`
	RetrievedAt time.Time        `json:"retrieved_at"`
	FreshUntil  time.Time        `json:"fresh_until"`
	StaleUntil  time.Time        `json:"stale_until"`
}

// IsFresh reports whether the cached allow is strictly within its fresh window.
func (ca CachedAllow) IsFresh(now time.Time) bool {
	normNow := normalizeTime(now)
	return !normNow.After(ca.FreshUntil)
}

// IsStale reports whether the cached allow is past its fresh window but within stale tolerance.
func (ca CachedAllow) IsStale(now time.Time) bool {
	normNow := normalizeTime(now)
	return normNow.After(ca.FreshUntil) && !normNow.After(ca.StaleUntil)
}

// IsExpired reports whether the cached allow is beyond both fresh and stale retention.
func (ca CachedAllow) IsExpired(now time.Time) bool {
	normNow := normalizeTime(now)
	return normNow.After(ca.StaleUntil)
}

type cacheEntry struct {
	outcome    Outcome
	freshUntil time.Time
	staleUntil time.Time
}

// Cache defines storage semantics for evidence outcomes and cached allow decisions.
type Cache interface {
	// Get retrieves an outcome for (kind, pkg, version) at evaluated time now.
	// Returns Available if fresh, Stale if past fresh but within stale tolerance, or false if expired/absent.
	Get(kind, pkg, version string, now time.Time) (Outcome, bool)

	// Put stores an evidence outcome in cache using its FreshUntil and computed stale tolerance.
	Put(pkg, version string, outcome Outcome, staleUntil time.Time)

	// GetCachedAllow retrieves a cached allow decision for (pkg, version).
	GetCachedAllow(pkg, version string, now time.Time) (CachedAllow, bool)

	// PutCachedAllow stores an evaluated allow decision for (pkg, version).
	PutCachedAllow(pkg, version string, d verdict.Decision, snapshotID string, retrievedAt, freshUntil, staleUntil time.Time)
}

// MemoryCache provides a thread-safe, in-memory implementation of Cache.
type MemoryCache struct {
	mu        sync.RWMutex
	evidence  map[string]cacheEntry
	decisions map[string]CachedAllow
}

// NewMemoryCache constructs an empty in-memory cache.
func NewMemoryCache() *MemoryCache {
	return &MemoryCache{
		evidence:  make(map[string]cacheEntry),
		decisions: make(map[string]CachedAllow),
	}
}

func evidenceKey(kind, pkg, version string) string {
	return kind + ":" + pkg + "@" + version
}

func decisionKey(pkg, version string) string {
	return pkg + "@" + version
}

// Get retrieves an evidence outcome, distinguishing fresh from stale-but-usable states.
func (mc *MemoryCache) Get(kind, pkg, version string, now time.Time) (Outcome, bool) {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	key := evidenceKey(kind, pkg, version)
	entry, ok := mc.evidence[key]
	if !ok {
		return Outcome{}, false
	}

	normNow := normalizeTime(now)

	// If within fresh window, return Available
	if !normNow.After(entry.freshUntil) {
		out := entry.outcome
		out.state = StateAvailable
		return out, true
	}

	// If within stale-tolerance window, return Stale
	if !normNow.After(entry.staleUntil) {
		out := entry.outcome
		out.state = StateStale
		out.reason = "served from cache: past freshness window but within stale tolerance"
		return out, true
	}

	// Beyond stale tolerance: expired
	return Outcome{}, false
}

// Put records an evidence outcome with its fresh and stale boundaries.
func (mc *MemoryCache) Put(pkg, version string, outcome Outcome, staleUntil time.Time) {
	if outcome.State() == StateUnavailable {
		// Never cache unavailable failures as evidence
		return
	}

	mc.mu.Lock()
	defer mc.mu.Unlock()

	key := evidenceKey(outcome.Kind(), pkg, version)
	mc.evidence[key] = cacheEntry{
		outcome:    outcome,
		freshUntil: outcome.FreshUntil(),
		staleUntil: normalizeTime(staleUntil),
	}
}

// GetCachedAllow retrieves a cached allow decision if not expired.
func (mc *MemoryCache) GetCachedAllow(pkg, version string, now time.Time) (CachedAllow, bool) {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	key := decisionKey(pkg, version)
	allow, ok := mc.decisions[key]
	if !ok {
		return CachedAllow{}, false
	}

	if allow.IsExpired(now) {
		return CachedAllow{}, false
	}

	return allow, true
}

// PutCachedAllow stores an evaluated allow decision.
func (mc *MemoryCache) PutCachedAllow(pkg, version string, d verdict.Decision, snapshotID string, retrievedAt, freshUntil, staleUntil time.Time) {
	if d.Verdict != verdict.Allow {
		// Only allow decisions are cached for degraded-mode fallback
		return
	}

	mc.mu.Lock()
	defer mc.mu.Unlock()

	key := decisionKey(pkg, version)
	mc.decisions[key] = CachedAllow{
		Decision:    d,
		SnapshotID:  snapshotID,
		RetrievedAt: normalizeTime(retrievedAt),
		FreshUntil:  normalizeTime(freshUntil),
		StaleUntil:  normalizeTime(staleUntil),
	}
}
