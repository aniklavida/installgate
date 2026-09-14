package evidence

import (
	"context"
	"time"

	"github.com/aniklavida/installgate/internal/verdict"
)

// Option configures an Assembler instance.
type Option func(*Assembler)

// WithClock sets a custom clock function for deterministic snapshot assembly.
func WithClock(clock func() time.Time) Option {
	return func(a *Assembler) {
		if clock != nil {
			a.clock = clock
		}
	}
}

// WithProviders registers evidence providers with the assembler.
func WithProviders(providers ...Provider) Option {
	return func(a *Assembler) {
		a.providers = append(a.providers, providers...)
	}
}

// WithCache sets the cache implementation used by the assembler.
func WithCache(c Cache) Option {
	return func(a *Assembler) {
		if c != nil {
			a.cache = c
		}
	}
}

// WithFreshnessPolicy sets the freshness policy used by the assembler.
func WithFreshnessPolicy(fp *FreshnessPolicy) Option {
	return func(a *Assembler) {
		if fp != nil {
			a.freshness = fp
		}
	}
}

// WithRequiredKinds specifies evidence kinds required for a complete snapshot.
func WithRequiredKinds(kinds ...string) Option {
	return func(a *Assembler) {
		a.requiredKinds = append(a.requiredKinds, kinds...)
	}
}

// Assembler coordinates clock, network providers, and caching to produce immutable Snapshots.
// It is the ONLY place in the system that touches the clock or the network.
type Assembler struct {
	clock         func() time.Time
	providers     []Provider
	cache         Cache
	freshness     *FreshnessPolicy
	requiredKinds []string
}

// NewAssembler constructs an Assembler with the given options.
func NewAssembler(opts ...Option) *Assembler {
	a := &Assembler{
		clock:     time.Now,
		cache:     NewMemoryCache(),
		freshness: DefaultFreshnessPolicy(),
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// Assemble collects observations from providers or cache for the given package coordinates,
// returning an immutable Snapshot with a stable identity.
func (a *Assembler) Assemble(ctx context.Context, pkg, version string) (Snapshot, error) {
	now := normalizeTime(a.clock())

	var observations []verdict.Signal
	states := make(map[string]State)

	// Check if a prior allow decision was cached for these coordinates
	if a.cache != nil {
		if cachedAllow, ok := a.cache.GetCachedAllow(pkg, version, now); ok {
			if cachedAllow.IsFresh(now) {
				observations = append(observations, verdict.Signal{
					Kind:        KindCache,
					Source:      "cache",
					Observation: "fresh_allow",
					Confidence:  ConfidenceHigh,
					RetrievedAt: cachedAllow.RetrievedAt,
					FreshUntil:  cachedAllow.FreshUntil,
				})
			} else if cachedAllow.IsStale(now) {
				observations = append(observations, verdict.Signal{
					Kind:        KindCache,
					Source:      "cache",
					Observation: "stale_allow",
					Confidence:  ConfidenceLow,
					RetrievedAt: cachedAllow.RetrievedAt,
					FreshUntil:  cachedAllow.FreshUntil,
				})
			}
		}
	}

	coveredKinds := make(map[string]bool)

	for _, p := range a.providers {
		kind := p.Kind()
		coveredKinds[kind] = true

		var outcome Outcome
		var cacheHit bool

		// Check cache for fresh evidence
		if a.cache != nil {
			if cached, ok := a.cache.Get(kind, pkg, version, now); ok {
				if cached.IsAvailable() {
					outcome = cached
					cacheHit = true
				} else if cached.IsStale() {
					// Keep stale cache entry in reserve if provider fails
					outcome = cached
				}
			}
		}

		// Fetch from live provider if not fresh in cache
		if !cacheHit {
			liveOutcome := p.Provide(ctx, Query{Package: pkg, Version: version})

			if liveOutcome.IsAvailable() {
				outcome = liveOutcome
				if a.cache != nil {
					staleUntil := a.freshness.StaleUntil(kind, liveOutcome.RetrievedAt())
					a.cache.Put(pkg, version, liveOutcome, staleUntil)
				}
			} else if liveOutcome.IsStale() || liveOutcome.IsDegraded() {
				outcome = liveOutcome
			} else {
				// Provider failed (Unavailable)
				if outcome.IsStale() {
					// Fall back to stale cache entry during provider outage
					states[kind] = StateStale
				} else {
					outcome = liveOutcome
				}
			}
		}

		states[kind] = outcome.State()

		for _, sig := range outcome.Signals() {
			if sig.RetrievedAt.IsZero() {
				sig.RetrievedAt = now
			}
			if sig.FreshUntil.IsZero() {
				sig.FreshUntil = a.freshness.FreshUntil(sig.Kind, sig.RetrievedAt)
			}
			observations = append(observations, sig)
		}
	}

	// Ensure any required kinds not covered by providers are visibly marked unavailable
	for _, reqKind := range a.requiredKinds {
		if !coveredKinds[reqKind] {
			states[reqKind] = StateUnavailable
			observations = append(observations, verdict.Signal{
				Kind:        reqKind,
				Source:      "assembler",
				Observation: "unavailable",
				Confidence:  ConfidenceNone,
				RetrievedAt: now,
				FreshUntil:  now,
			})
		}
	}

	snap := NewSnapshot(pkg, version, observations, states, now)
	return snap, nil
}
