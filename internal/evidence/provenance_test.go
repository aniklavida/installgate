package evidence

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProvenanceProviderMaintainerSetChanged(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(packumentProvenanceDoc{
			Name: "sec-pkg",
			Time: map[string]string{
				"created": now.Add(-100 * 24 * time.Hour).Format(time.RFC3339Nano),
				"1.0.0":   now.Add(-100 * 24 * time.Hour).Format(time.RFC3339Nano),
				"1.0.1":   now.Add(-1 * time.Hour).Format(time.RFC3339Nano),
			},
			Versions: map[string]npmVersionProvenanceMeta{
				"1.0.0": {
					Version:     "1.0.0",
					Maintainers: []npmUserMeta{{Name: "alice"}},
				},
				"1.0.1": {
					Version:     "1.0.1",
					Maintainers: []npmUserMeta{{Name: "bob"}}, // different maintainer!
				},
			},
		})
	}))
	defer server.Close()

	p := NewProvenanceProvider(
		WithProvenanceRegistryURL(server.URL),
		WithProvenanceClock(func() time.Time { return now }),
	)

	outcome := p.Provide(context.Background(), Query{Package: "sec-pkg", Version: "1.0.1"})
	if outcome.State() != StateAvailable {
		t.Fatalf("expected StateAvailable, got %v", outcome.State())
	}

	sigs := outcome.Signals()
	var hasChanged, hasMaintainerChanged bool
	for _, s := range sigs {
		if s.Kind == KindProvenance && s.Observation == "changed" {
			hasChanged = true
		}
		if s.Kind == KindProvenance && s.Observation == "maintainer_set_changed" {
			hasMaintainerChanged = true
		}
	}

	if !hasChanged {
		t.Fatalf("expected KindProvenance 'changed' signal, got %+v", sigs)
	}
	if !hasMaintainerChanged {
		t.Fatalf("expected KindProvenance 'maintainer_set_changed' signal, got %+v", sigs)
	}
}

func TestProvenanceProviderPublisherChanged(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(packumentProvenanceDoc{
			Name: "sec-pkg",
			Time: map[string]string{
				"created": now.Add(-50 * 24 * time.Hour).Format(time.RFC3339Nano),
				"1.0.0":   now.Add(-50 * 24 * time.Hour).Format(time.RFC3339Nano),
				"1.1.0":   now.Add(-2 * time.Hour).Format(time.RFC3339Nano),
			},
			Versions: map[string]npmVersionProvenanceMeta{
				"1.0.0": {
					Version:     "1.0.0",
					Maintainers: []npmUserMeta{{Name: "alice"}},
					NpmUser:     npmUserMeta{Name: "alice"},
				},
				"1.1.0": {
					Version:     "1.1.0",
					Maintainers: []npmUserMeta{{Name: "alice"}},
					NpmUser:     npmUserMeta{Name: "untrusted-stranger"}, // stranger published
				},
			},
		})
	}))
	defer server.Close()

	p := NewProvenanceProvider(
		WithProvenanceRegistryURL(server.URL),
		WithProvenanceClock(func() time.Time { return now }),
	)

	outcome := p.Provide(context.Background(), Query{Package: "sec-pkg", Version: "1.1.0"})
	if outcome.State() != StateAvailable {
		t.Fatalf("expected StateAvailable, got %v", outcome.State())
	}

	sigs := outcome.Signals()
	var hasChanged, hasNewPublisher bool
	for _, s := range sigs {
		if s.Kind == KindProvenance && s.Observation == "changed" {
			hasChanged = true
		}
		if s.Kind == KindProvenance && s.Observation == "new_unrecognized_publisher" {
			hasNewPublisher = true
		}
	}

	if !hasChanged || !hasNewPublisher {
		t.Fatalf("expected new unrecognized publisher signals, got %+v", sigs)
	}
}

func TestProvenanceProviderRepositoryChanged(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(packumentProvenanceDoc{
			Name: "sec-pkg",
			Time: map[string]string{
				"created": now.Add(-50 * 24 * time.Hour).Format(time.RFC3339Nano),
				"1.0.0":   now.Add(-50 * 24 * time.Hour).Format(time.RFC3339Nano),
				"1.1.0":   now.Add(-2 * time.Hour).Format(time.RFC3339Nano),
			},
			Versions: map[string]npmVersionProvenanceMeta{
				"1.0.0": {
					Version:    "1.0.0",
					Repository: "https://github.com/legit-org/sec-pkg",
				},
				"1.1.0": {
					Version:    "1.1.0",
					Repository: "https://github.com/attacker-org/sec-pkg", // repo changed!
				},
			},
		})
	}))
	defer server.Close()

	p := NewProvenanceProvider(
		WithProvenanceRegistryURL(server.URL),
		WithProvenanceClock(func() time.Time { return now }),
	)

	outcome := p.Provide(context.Background(), Query{Package: "sec-pkg", Version: "1.1.0"})
	if outcome.State() != StateAvailable {
		t.Fatalf("expected StateAvailable, got %v", outcome.State())
	}

	sigs := outcome.Signals()
	var hasRepoChanged bool
	for _, s := range sigs {
		if s.Observation == "repository_changed" {
			hasRepoChanged = true
		}
	}
	if !hasRepoChanged {
		t.Fatalf("expected repository_changed signal, got %+v", sigs)
	}
}

func TestProvenanceProviderAttestationPresenceAndRemoval(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)

	// Case A: Attestation present
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(packumentProvenanceDoc{
			Name: "attested-pkg",
			Time: map[string]string{
				"created": now.Add(-10 * 24 * time.Hour).Format(time.RFC3339Nano),
				"1.0.0":   now.Add(-10 * 24 * time.Hour).Format(time.RFC3339Nano),
				"2.0.0":   now.Add(-1 * time.Hour).Format(time.RFC3339Nano),
			},
			Versions: map[string]npmVersionProvenanceMeta{
				"1.0.0": {
					Version: "1.0.0",
					Dist: npmDistMeta{
						Attestations: map[string]interface{}{"url": "https://registry.npmjs.org/-/attestations/1"},
					},
				},
				"2.0.0": {
					Version: "2.0.0",
					Dist:    npmDistMeta{
						// Attestations removed in v2!
					},
				},
			},
		})
	}))
	defer server.Close()

	p := NewProvenanceProvider(
		WithProvenanceRegistryURL(server.URL),
		WithProvenanceClock(func() time.Time { return now }),
	)

	// Check v1 has attestation present
	outcomeV1 := p.Provide(context.Background(), Query{Package: "attested-pkg", Version: "1.0.0"})
	var v1AttestationPresent bool
	for _, s := range outcomeV1.Signals() {
		if s.Observation == "attestation_present" {
			v1AttestationPresent = true
		}
	}
	if !v1AttestationPresent {
		t.Fatalf("expected attestation_present for v1, got %+v", outcomeV1.Signals())
	}

	// Check v2 has attestation removed!
	outcomeV2 := p.Provide(context.Background(), Query{Package: "attested-pkg", Version: "2.0.0"})
	var v2AttestationRemoved, v2Changed bool
	for _, s := range outcomeV2.Signals() {
		if s.Observation == "attestation_removed" {
			v2AttestationRemoved = true
		}
		if s.Observation == "changed" {
			v2Changed = true
		}
	}
	if !v2AttestationRemoved || !v2Changed {
		t.Fatalf("expected attestation_removed and changed signals for v2, got %+v", outcomeV2.Signals())
	}
}

func TestProvenanceProviderUnchanged(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(packumentProvenanceDoc{
			Name: "stable-pkg",
			Time: map[string]string{
				"created": now.Add(-100 * 24 * time.Hour).Format(time.RFC3339Nano),
				"1.0.0":   now.Add(-100 * 24 * time.Hour).Format(time.RFC3339Nano),
				"1.0.1":   now.Add(-10 * time.Hour).Format(time.RFC3339Nano),
			},
			Versions: map[string]npmVersionProvenanceMeta{
				"1.0.0": {
					Version:     "1.0.0",
					Maintainers: []npmUserMeta{{Name: "alice"}},
					NpmUser:     npmUserMeta{Name: "alice"},
					Repository:  "https://github.com/alice/stable-pkg",
				},
				"1.0.1": {
					Version:     "1.0.1",
					Maintainers: []npmUserMeta{{Name: "alice"}},
					NpmUser:     npmUserMeta{Name: "alice"},
					Repository:  "https://github.com/alice/stable-pkg",
				},
			},
		})
	}))
	defer server.Close()

	p := NewProvenanceProvider(
		WithProvenanceRegistryURL(server.URL),
		WithProvenanceClock(func() time.Time { return now }),
	)

	outcome := p.Provide(context.Background(), Query{Package: "stable-pkg", Version: "1.0.1"})
	if outcome.State() != StateAvailable {
		t.Fatalf("expected StateAvailable, got %v", outcome.State())
	}

	sigs := outcome.Signals()
	var hasUnchanged bool
	for _, s := range sigs {
		if s.Observation == "unchanged" {
			hasUnchanged = true
		}
	}
	if !hasUnchanged {
		t.Fatalf("expected unchanged signal, got %+v", sigs)
	}
}

func TestProvenanceProviderConflictingMissingPreviousVersionInMap(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(packumentProvenanceDoc{
			Name: "broken-pkg",
			Time: map[string]string{
				"created": now.Add(-50 * 24 * time.Hour).Format(time.RFC3339Nano),
				"1.0.0":   now.Add(-50 * 24 * time.Hour).Format(time.RFC3339Nano),
				"1.1.0":   now.Add(-2 * time.Hour).Format(time.RFC3339Nano),
			},
			Versions: map[string]npmVersionProvenanceMeta{
				// 1.0.0 missing from versions map!
				"1.1.0": {Version: "1.1.0"},
			},
		})
	}))
	defer server.Close()

	p := NewProvenanceProvider(
		WithProvenanceRegistryURL(server.URL),
		WithProvenanceClock(func() time.Time { return now }),
	)

	outcome := p.Provide(context.Background(), Query{Package: "broken-pkg", Version: "1.1.0"})
	if outcome.State() != StateDegraded {
		t.Fatalf("expected StateDegraded on missing previous version in versions map, got %v", outcome.State())
	}
}

func TestProvenanceProviderStaleHeader(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Warning", `110 - "Response is Stale"`)
		_ = json.NewEncoder(w).Encode(packumentProvenanceDoc{
			Name: "stale-pkg",
			Time: map[string]string{
				"created": now.Format(time.RFC3339Nano),
				"1.0.0":   now.Format(time.RFC3339Nano),
			},
			Versions: map[string]npmVersionProvenanceMeta{
				"1.0.0": {Version: "1.0.0"},
			},
		})
	}))
	defer server.Close()

	p := NewProvenanceProvider(
		WithProvenanceRegistryURL(server.URL),
		WithProvenanceClock(func() time.Time { return now }),
	)

	outcome := p.Provide(context.Background(), Query{Package: "stale-pkg", Version: "1.0.0"})
	if outcome.State() != StateStale {
		t.Fatalf("expected StateStale, got %v", outcome.State())
	}
	if !outcome.IsStale() {
		t.Fatal("IsStale() must return true")
	}
}

func TestProvenanceProviderUnavailableHttp500(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer server.Close()

	p := NewProvenanceProvider(
		WithProvenanceRegistryURL(server.URL),
	)

	outcome := p.Provide(context.Background(), Query{Package: "pkg", Version: "1.0.0"})
	if outcome.State() != StateUnavailable {
		t.Fatalf("expected StateUnavailable on 500, got %v", outcome.State())
	}
}

func TestProvenanceProviderUnavailableEmptyBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// 0 bytes
	}))
	defer server.Close()

	p := NewProvenanceProvider(
		WithProvenanceRegistryURL(server.URL),
	)

	outcome := p.Provide(context.Background(), Query{Package: "pkg", Version: "1.0.0"})
	if outcome.State() != StateUnavailable {
		t.Fatalf("expected StateUnavailable on empty body, got %v", outcome.State())
	}
	sigs := outcome.Signals()
	if len(sigs) == 0 || sigs[0].Observation != "unavailable" {
		t.Fatalf("expected unavailable signal, got %+v", sigs)
	}
}
