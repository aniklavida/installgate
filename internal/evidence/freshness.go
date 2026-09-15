package evidence

import (
	"sync"
	"time"

	"github.com/aniklavida/installgate/internal/verdict"
)

// Evidence kind constants matching policy and verdict expectations.
const (
	KindIntegrity      = "integrity"
	KindMalicious      = "malicious"
	KindVulnerability  = "vulnerability"
	KindAvailability   = "availability"
	KindCache          = "cache"
	KindNameConfusion  = "name_confusion"
	KindPackageAge     = "package_age"
	KindProvenance     = "provenance"
	KindInstallScript  = "install_script"
	KindReputation     = "reputation"
	KindPublishHistory = "publish_history"
	KindDecisionAllow  = "decision_allow"
)

// Confidence level constants.
const (
	ConfidenceHigh   = "high"
	ConfidenceMedium = "medium"
	ConfidenceLow    = "low"
	ConfidenceNone   = "none"
)

// Signal and Observation are aliases to the canonical verdict.Signal shape.
type Signal = verdict.Signal
type Observation = verdict.Signal

// normalizeTime ensures timestamps are in UTC, monotonic-clock stripped,
// and millisecond-truncated for deterministic JSON serialization and hashing.
func normalizeTime(t time.Time) time.Time {
	if t.IsZero() {
		return time.Time{}
	}
	return t.UTC().Truncate(time.Millisecond)
}

// FreshnessConfig defines the fresh and stale-tolerance windows for an evidence kind.
type FreshnessConfig struct {
	FreshTTL time.Duration `json:"fresh_ttl"`
	StaleTTL time.Duration `json:"stale_ttl"`
}

// FreshnessPolicy maintains per-kind freshness windows.
type FreshnessPolicy struct {
	mu      sync.RWMutex
	configs map[string]FreshnessConfig
}

// DefaultFreshnessConfigs returns production-grade freshness windows per evidence kind.
// Advisory and publish-history records intentionally age at different rates.
func DefaultFreshnessConfigs() map[string]FreshnessConfig {
	return map[string]FreshnessConfig{
		KindVulnerability: {
			FreshTTL: 1 * time.Hour,
			StaleTTL: 24 * time.Hour,
		},
		KindPublishHistory: {
			FreshTTL: 15 * time.Minute,
			StaleTTL: 12 * time.Hour,
		},
		KindPackageAge: {
			FreshTTL: 15 * time.Minute,
			StaleTTL: 12 * time.Hour,
		},
		KindMalicious: {
			FreshTTL: 1 * time.Hour,
			StaleTTL: 24 * time.Hour,
		},
		KindIntegrity: {
			FreshTTL: 24 * time.Hour,
			StaleTTL: 7 * 24 * time.Hour,
		},
		KindProvenance: {
			FreshTTL: 6 * time.Hour,
			StaleTTL: 48 * time.Hour,
		},
		KindReputation: {
			FreshTTL: 24 * time.Hour,
			StaleTTL: 7 * 24 * time.Hour,
		},
		KindInstallScript: {
			FreshTTL: 7 * 24 * time.Hour,
			StaleTTL: 30 * 24 * time.Hour,
		},
		KindNameConfusion: {
			FreshTTL: 12 * time.Hour,
			StaleTTL: 72 * time.Hour,
		},
		KindDecisionAllow: {
			FreshTTL: 30 * time.Minute,
			StaleTTL: 6 * time.Hour,
		},
		KindCache: {
			FreshTTL: 30 * time.Minute,
			StaleTTL: 6 * time.Hour,
		},
	}
}

// NewFreshnessPolicy constructs a freshness policy with optional overrides.
func NewFreshnessPolicy(custom map[string]FreshnessConfig) *FreshnessPolicy {
	configs := DefaultFreshnessConfigs()
	for k, v := range custom {
		configs[k] = v
	}
	return &FreshnessPolicy{configs: configs}
}

// DefaultFreshnessPolicy returns the default freshness policy.
func DefaultFreshnessPolicy() *FreshnessPolicy {
	return NewFreshnessPolicy(nil)
}

// Config retrieves the freshness config for a given evidence kind.
// Returns a conservative fallback if the kind has not been explicitly configured.
func (fp *FreshnessPolicy) Config(kind string) FreshnessConfig {
	fp.mu.RLock()
	defer fp.mu.RUnlock()
	cfg, ok := fp.configs[kind]
	if ok {
		return cfg
	}
	return FreshnessConfig{
		FreshTTL: 1 * time.Hour,
		StaleTTL: 12 * time.Hour,
	}
}

// SetConfig sets or overrides the freshness config for a specific evidence kind.
func (fp *FreshnessPolicy) SetConfig(kind string, cfg FreshnessConfig) {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	fp.configs[kind] = cfg
}

// FreshUntil computes the timestamp when freshness expires for a retrieved observation.
func (fp *FreshnessPolicy) FreshUntil(kind string, retrievedAt time.Time) time.Time {
	cfg := fp.Config(kind)
	return normalizeTime(retrievedAt.Add(cfg.FreshTTL))
}

// StaleUntil computes the latest timestamp through which an observation remains stale-but-usable.
func (fp *FreshnessPolicy) StaleUntil(kind string, retrievedAt time.Time) time.Time {
	cfg := fp.Config(kind)
	return normalizeTime(retrievedAt.Add(cfg.FreshTTL + cfg.StaleTTL))
}

// Classify determines the freshness state of an observation retrieved at retrievedAt as evaluated at now.
func (fp *FreshnessPolicy) Classify(kind string, retrievedAt, now time.Time) State {
	normRet := normalizeTime(retrievedAt)
	normNow := normalizeTime(now)
	freshUntil := fp.FreshUntil(kind, normRet)
	if !normNow.After(freshUntil) {
		return StateAvailable
	}
	staleUntil := fp.StaleUntil(kind, normRet)
	if !normNow.After(staleUntil) {
		return StateStale
	}
	return StateUnavailable
}
