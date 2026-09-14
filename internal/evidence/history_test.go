package evidence

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHistoryProviderFreshNewborn(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	created := now.Add(-2 * time.Hour) // 2 hours old -> newborn

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(packumentTimeDoc{
			Name: "newborn-pkg",
			Time: map[string]string{
				"created": created.Format(time.RFC3339Nano),
				"1.0.0":   created.Format(time.RFC3339Nano),
			},
			Versions: map[string]interface{}{
				"1.0.0": map[string]interface{}{},
			},
		})
	}))
	defer server.Close()

	p := NewHistoryProvider(
		WithHistoryRegistryURL(server.URL),
		WithHistoryClock(func() time.Time { return now }),
	)

	outcome := p.Provide(context.Background(), Query{Package: "newborn-pkg", Version: "1.0.0"})
	if outcome.State() != StateAvailable {
		t.Fatalf("expected StateAvailable, got %v", outcome.State())
	}

	sigs := outcome.Signals()
	var hasNewborn bool
	for _, s := range sigs {
		if s.Kind == KindPackageAge && s.Observation == "newborn" {
			hasNewborn = true
		}
	}
	if !hasNewborn {
		t.Fatalf("expected KindPackageAge newborn signal, got %+v", sigs)
	}
}

func TestHistoryProviderFreshVersion(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	created := now.Add(-365 * 24 * time.Hour) // 1 year old package
	v2Time := now.Add(-3 * time.Hour)         // version 2.0.0 published 3h ago -> fresh version

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(packumentTimeDoc{
			Name: "established-pkg",
			Time: map[string]string{
				"created": created.Format(time.RFC3339Nano),
				"1.0.0":   created.Format(time.RFC3339Nano),
				"2.0.0":   v2Time.Format(time.RFC3339Nano),
			},
			Versions: map[string]interface{}{
				"1.0.0": map[string]interface{}{},
				"2.0.0": map[string]interface{}{},
			},
		})
	}))
	defer server.Close()

	p := NewHistoryProvider(
		WithHistoryRegistryURL(server.URL),
		WithHistoryClock(func() time.Time { return now }),
	)

	outcome := p.Provide(context.Background(), Query{Package: "established-pkg", Version: "2.0.0"})
	if outcome.State() != StateAvailable {
		t.Fatalf("expected StateAvailable, got %v", outcome.State())
	}

	sigs := outcome.Signals()
	var hasFresh bool
	for _, s := range sigs {
		if s.Kind == KindPackageAge && s.Observation == "fresh" {
			hasFresh = true
		}
	}
	if !hasFresh {
		t.Fatalf("expected KindPackageAge fresh signal, got %+v", sigs)
	}
}

func TestHistoryProviderDormantReleaseRevival(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	v1Time := now.Add(-400 * 24 * time.Hour) // published 400 days ago
	v2Time := now.Add(-10 * time.Hour)       // gap = 399 days (> 180 days dormant)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(packumentTimeDoc{
			Name: "dormant-pkg",
			Time: map[string]string{
				"created": v1Time.Format(time.RFC3339Nano),
				"1.0.0":   v1Time.Format(time.RFC3339Nano),
				"1.0.1":   v2Time.Format(time.RFC3339Nano),
			},
			Versions: map[string]interface{}{
				"1.0.0": map[string]interface{}{},
				"1.0.1": map[string]interface{}{},
			},
		})
	}))
	defer server.Close()

	p := NewHistoryProvider(
		WithHistoryRegistryURL(server.URL),
		WithHistoryClock(func() time.Time { return now }),
	)

	outcome := p.Provide(context.Background(), Query{Package: "dormant-pkg", Version: "1.0.1"})
	if outcome.State() != StateAvailable {
		t.Fatalf("expected StateAvailable, got %v", outcome.State())
	}

	sigs := outcome.Signals()
	var hasDormantRevival bool
	for _, s := range sigs {
		if s.Kind == KindPublishHistory && s.Observation == "dormant_revival" {
			hasDormantRevival = true
		}
	}
	if !hasDormantRevival {
		t.Fatalf("expected KindPublishHistory dormant_revival signal, got %+v", sigs)
	}
}

func TestHistoryProviderNonexistentPackageNoMaliciousLanguage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"Not found"}`, http.StatusNotFound)
	}))
	defer server.Close()

	p := NewHistoryProvider(
		WithHistoryRegistryURL(server.URL),
	)

	outcome := p.Provide(context.Background(), Query{Package: "nonexistent-pkg-abc", Version: "1.0.0"})
	if outcome.State() != StateAvailable {
		t.Fatalf("expected StateAvailable for definite 404, got %v", outcome.State())
	}

	sigs := outcome.Signals()
	if len(sigs) == 0 {
		t.Fatal("expected signals for nonexistent package")
	}

	// Hard constraint: A nonexistent package fails as nonexistent and is NEVER labelled malicious.
	// A nonexistent package produces a clear not-found result containing no malicious language, asserted by test.
	for _, s := range sigs {
		obsLower := strings.ToLower(s.Observation)
		if strings.Contains(obsLower, "malicious") || strings.Contains(obsLower, "malware") {
			t.Fatalf("malicious language forbidden for nonexistent package: %q", s.Observation)
		}
	}

	var hasNotFound bool
	for _, s := range sigs {
		if s.Observation == "not_found" {
			hasNotFound = true
		}
	}
	if !hasNotFound {
		t.Fatalf("expected not_found signal, got %+v", sigs)
	}
}

func TestHistoryProviderNonexistentVersion(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(packumentTimeDoc{
			Name: "my-pkg",
			Time: map[string]string{
				"created": now.Add(-48 * time.Hour).Format(time.RFC3339Nano),
				"1.0.0":   now.Add(-48 * time.Hour).Format(time.RFC3339Nano),
			},
			Versions: map[string]interface{}{
				"1.0.0": map[string]interface{}{},
			},
		})
	}))
	defer server.Close()

	p := NewHistoryProvider(
		WithHistoryRegistryURL(server.URL),
		WithHistoryClock(func() time.Time { return now }),
	)

	outcome := p.Provide(context.Background(), Query{Package: "my-pkg", Version: "9.9.9"})
	if outcome.State() != StateAvailable {
		t.Fatalf("expected StateAvailable, got %v", outcome.State())
	}

	sigs := outcome.Signals()
	var hasVersionNotFound bool
	for _, s := range sigs {
		if s.Observation == "version_not_found" {
			hasVersionNotFound = true
		}
	}
	if !hasVersionNotFound {
		t.Fatalf("expected version_not_found signal, got %+v", sigs)
	}
}

func TestHistoryProviderStaleHeader(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Warning", `110 - "Response is Stale"`)
		_ = json.NewEncoder(w).Encode(packumentTimeDoc{
			Name: "stale-pkg",
			Time: map[string]string{
				"created": now.Add(-48 * time.Hour).Format(time.RFC3339Nano),
				"1.0.0":   now.Add(-48 * time.Hour).Format(time.RFC3339Nano),
			},
			Versions: map[string]interface{}{
				"1.0.0": map[string]interface{}{},
			},
		})
	}))
	defer server.Close()

	p := NewHistoryProvider(
		WithHistoryRegistryURL(server.URL),
		WithHistoryClock(func() time.Time { return now }),
	)

	outcome := p.Provide(context.Background(), Query{Package: "stale-pkg", Version: "1.0.0"})
	if outcome.State() != StateStale {
		t.Fatalf("expected StateStale, got %v", outcome.State())
	}
	if !outcome.IsStale() {
		t.Fatal("IsStale() must return true")
	}
}

func TestHistoryProviderConflictingFutureTimestamp(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	futureTime := now.Add(24 * time.Hour) // 24 hours in the future -> conflicting

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(packumentTimeDoc{
			Name: "future-pkg",
			Time: map[string]string{
				"created": now.Format(time.RFC3339Nano),
				"1.0.0":   futureTime.Format(time.RFC3339Nano),
			},
			Versions: map[string]interface{}{
				"1.0.0": map[string]interface{}{},
			},
		})
	}))
	defer server.Close()

	p := NewHistoryProvider(
		WithHistoryRegistryURL(server.URL),
		WithHistoryClock(func() time.Time { return now }),
	)

	outcome := p.Provide(context.Background(), Query{Package: "future-pkg", Version: "1.0.0"})
	if outcome.State() != StateDegraded {
		t.Fatalf("expected StateDegraded on future timestamp conflict, got %v", outcome.State())
	}
}

func TestHistoryProviderUnavailableHttp500(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal registry error", http.StatusInternalServerError)
	}))
	defer server.Close()

	p := NewHistoryProvider(
		WithHistoryRegistryURL(server.URL),
	)

	outcome := p.Provide(context.Background(), Query{Package: "err-pkg", Version: "1.0.0"})
	if outcome.State() != StateUnavailable {
		t.Fatalf("expected StateUnavailable on 500, got %v", outcome.State())
	}
	sigs := outcome.Signals()
	if len(sigs) == 0 || sigs[0].Observation != "unavailable" {
		t.Fatalf("expected unavailable signal, got %+v", sigs)
	}
}

func TestHistoryProviderUnavailableEmptyBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// 0 bytes
	}))
	defer server.Close()

	p := NewHistoryProvider(
		WithHistoryRegistryURL(server.URL),
	)

	outcome := p.Provide(context.Background(), Query{Package: "pkg", Version: "1.0.0"})
	if outcome.State() != StateUnavailable {
		t.Fatalf("expected StateUnavailable on empty body, got %v", outcome.State())
	}
	sigs := outcome.Signals()
	if len(sigs) == 0 || sigs[0].Observation != "unavailable" {
		t.Fatalf("expected unavailable signal on empty body, got %+v", sigs)
	}
}
