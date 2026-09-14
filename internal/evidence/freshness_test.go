package evidence

import (
	"testing"
	"time"
)

func TestPerKindFreshnessAging(t *testing.T) {
	policy := DefaultFreshnessPolicy()
	retrievedAt := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)

	// Verify advisory (vulnerability) and publish-history age at different rates
	vulnConfig := policy.Config(KindVulnerability)
	historyConfig := policy.Config(KindPublishHistory)
	integrityConfig := policy.Config(KindIntegrity)

	if vulnConfig.FreshTTL == historyConfig.FreshTTL {
		t.Fatalf("vulnerability and publish-history must not have identical fresh TTL: %v == %v",
			vulnConfig.FreshTTL, historyConfig.FreshTTL)
	}

	if integrityConfig.FreshTTL <= vulnConfig.FreshTTL {
		t.Fatalf("integrity fresh TTL (%v) should exceed vulnerability fresh TTL (%v)",
			integrityConfig.FreshTTL, vulnConfig.FreshTTL)
	}

	// At +20 minutes:
	// publish-history (fresh 15m, stale 12h) should be Stale
	// vulnerability (fresh 1h, stale 24h) should still be Available
	t20m := retrievedAt.Add(20 * time.Minute)
	if s := policy.Classify(KindPublishHistory, retrievedAt, t20m); s != StateStale {
		t.Fatalf("publish-history at +20m must be StateStale, got %v", s)
	}
	if s := policy.Classify(KindVulnerability, retrievedAt, t20m); s != StateAvailable {
		t.Fatalf("vulnerability at +20m must be StateAvailable, got %v", s)
	}

	// At +2 hours:
	// vulnerability should now be Stale
	t2h := retrievedAt.Add(2 * time.Hour)
	if s := policy.Classify(KindVulnerability, retrievedAt, t2h); s != StateStale {
		t.Fatalf("vulnerability at +2h must be StateStale, got %v", s)
	}

	// At +30 hours:
	// vulnerability (fresh 1h + stale 24h = 25h) is expired -> StateUnavailable
	t30h := retrievedAt.Add(30 * time.Hour)
	if s := policy.Classify(KindVulnerability, retrievedAt, t30h); s != StateUnavailable {
		t.Fatalf("vulnerability at +30h must be StateUnavailable (expired), got %v", s)
	}
}

func TestCustomFreshnessPolicy(t *testing.T) {
	custom := map[string]FreshnessConfig{
		KindVulnerability: {
			FreshTTL: 5 * time.Minute,
			StaleTTL: 10 * time.Minute,
		},
	}
	policy := NewFreshnessPolicy(custom)
	retrievedAt := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)

	if s := policy.Classify(KindVulnerability, retrievedAt, retrievedAt.Add(3*time.Minute)); s != StateAvailable {
		t.Fatalf("expected StateAvailable, got %v", s)
	}
	if s := policy.Classify(KindVulnerability, retrievedAt, retrievedAt.Add(7*time.Minute)); s != StateStale {
		t.Fatalf("expected StateStale, got %v", s)
	}
	if s := policy.Classify(KindVulnerability, retrievedAt, retrievedAt.Add(16*time.Minute)); s != StateUnavailable {
		t.Fatalf("expected StateUnavailable, got %v", s)
	}
}
