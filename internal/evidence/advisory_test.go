package evidence

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestAdvisoryProviderFreshWithVulnerability(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/query" {
			http.NotFound(w, r)
			return
		}
		var q osvSingleQuery
		_ = json.NewDecoder(r.Body).Decode(&q)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(osvQueryResponse{
			Vulns: []osvVulnerability{
				{
					ID:      "GHSA-1234-5678-90ab",
					Summary: "Remote Code Execution",
					Affected: []osvAffected{
						{
							Package: osvPackageRef{Name: q.Package.Name, Ecosystem: "npm"},
							Ranges: []osvRange{
								{
									Type: "SEMVER",
									Events: []osvEvent{
										{Introduced: "0"},
										{Fixed: "1.2.3"},
									},
								},
							},
						},
					},
				},
			},
		})
	}))
	defer server.Close()

	p := NewAdvisoryProvider(
		WithAdvisoryBaseURL(server.URL),
		WithAdvisoryClock(func() time.Time { return time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC) }),
	)

	outcome := p.Provide(context.Background(), Query{Package: "vulnerable-pkg", Version: "1.0.0"})
	if outcome.State() != StateAvailable {
		t.Fatalf("expected StateAvailable, got %v", outcome.State())
	}

	sigs := outcome.Signals()
	var hasAboveThreshold, hasSafeSuggestion bool
	for _, s := range sigs {
		if s.Kind == KindVulnerability && s.Observation == "above_threshold" {
			hasAboveThreshold = true
		}
		if s.Kind == KindVulnerability && s.Observation == "safe_version_suggested:1.2.3" {
			hasSafeSuggestion = true
		}
	}

	if !hasAboveThreshold {
		t.Fatalf("expected above_threshold signal, got %+v", sigs)
	}
	if !hasSafeSuggestion {
		t.Fatalf("expected safe_version_suggested:1.2.3 signal, got %+v", sigs)
	}
}

func TestAdvisoryProviderFreshWithMaliciousPackage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(osvQueryResponse{
			Vulns: []osvVulnerability{
				{
					ID:      "MAL-2026-999",
					Summary: "Malicious package drop malware",
					DatabaseSpecific: map[string]interface{}{
						"malicious": true,
					},
				},
			},
		})
	}))
	defer server.Close()

	p := NewAdvisoryProvider(
		WithAdvisoryBaseURL(server.URL),
		WithAdvisoryClock(func() time.Time { return time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC) }),
	)

	outcome := p.Provide(context.Background(), Query{Package: "malicious-lib", Version: "1.0.0"})
	if outcome.State() != StateAvailable {
		t.Fatalf("expected StateAvailable, got %v", outcome.State())
	}

	sigs := outcome.Signals()
	var hasMaliciousKind, hasMaliciousObs bool
	for _, s := range sigs {
		if s.Kind == KindMalicious && s.Observation == "malicious" {
			hasMaliciousKind = true
		}
		if s.Kind == KindVulnerability && s.Observation == "malicious" {
			hasMaliciousObs = true
		}
	}

	if !hasMaliciousKind {
		t.Fatalf("expected KindMalicious signal, got %+v", sigs)
	}
	if !hasMaliciousObs {
		t.Fatalf("expected KindVulnerability malicious observation, got %+v", sigs)
	}
}

func TestAdvisoryProviderFreshAbsenceNeverProofOfSafety(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(osvQueryResponse{
			Vulns: []osvVulnerability{},
		})
	}))
	defer server.Close()

	p := NewAdvisoryProvider(
		WithAdvisoryBaseURL(server.URL),
		WithAdvisoryClock(func() time.Time { return time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC) }),
	)

	outcome := p.Provide(context.Background(), Query{Package: "any-pkg", Version: "1.0.0"})
	if outcome.State() != StateAvailable {
		t.Fatalf("expected StateAvailable, got %v", outcome.State())
	}

	sigs := outcome.Signals()
	if len(sigs) != 1 {
		t.Fatalf("expected 1 signal, got %d", len(sigs))
	}
	// Hard constraint: Absence of an advisory is recorded as 'no record found at this retrieval time',
	// NEVER as evidence of safety.
	if sigs[0].Observation != "no_record_found" {
		t.Fatalf("expected observation 'no_record_found', got %q", sigs[0].Observation)
	}
	if sigs[0].Observation == "safe" || sigs[0].Observation == "none" {
		t.Fatalf("observation must not imply proof of safety: %q", sigs[0].Observation)
	}
}

func TestAdvisoryProviderStaleHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Warning", `110 - "Response is Stale"`)
		_ = json.NewEncoder(w).Encode(osvQueryResponse{
			Vulns: []osvVulnerability{},
		})
	}))
	defer server.Close()

	p := NewAdvisoryProvider(
		WithAdvisoryBaseURL(server.URL),
		WithAdvisoryClock(func() time.Time { return time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC) }),
	)

	outcome := p.Provide(context.Background(), Query{Package: "pkg", Version: "1.0.0"})
	if outcome.State() != StateStale {
		t.Fatalf("expected StateStale, got %v", outcome.State())
	}
	if !outcome.IsStale() {
		t.Fatal("IsStale() must return true")
	}
	if outcome.Reason() == "" {
		t.Fatal("stale outcome should have explanatory reason")
	}
}

func TestAdvisoryProviderConflictingMalformedPayload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{not valid json`))
	}))
	defer server.Close()

	p := NewAdvisoryProvider(
		WithAdvisoryBaseURL(server.URL),
	)

	outcome := p.Provide(context.Background(), Query{Package: "pkg", Version: "1.0.0"})
	if outcome.State() != StateUnavailable {
		t.Fatalf("expected StateUnavailable on malformed json, got %v", outcome.State())
	}
	if outcome.Err() == nil {
		t.Fatal("expected error on malformed json")
	}
}

func TestAdvisoryProviderUnavailableHttp500(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream server error", http.StatusInternalServerError)
	}))
	defer server.Close()

	p := NewAdvisoryProvider(
		WithAdvisoryBaseURL(server.URL),
	)

	outcome := p.Provide(context.Background(), Query{Package: "pkg", Version: "1.0.0"})
	if outcome.State() != StateUnavailable {
		t.Fatalf("expected StateUnavailable on 500, got %v", outcome.State())
	}
	sigs := outcome.Signals()
	if len(sigs) == 0 || sigs[0].Observation != "unavailable" {
		t.Fatalf("expected explicit unavailable signal, got %+v", sigs)
	}
}

func TestAdvisoryProviderUnavailableTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	p := NewAdvisoryProvider(
		WithAdvisoryBaseURL(server.URL),
		WithAdvisoryTimeout(20*time.Millisecond),
	)

	outcome := p.Provide(context.Background(), Query{Package: "pkg", Version: "1.0.0"})
	if outcome.State() != StateUnavailable {
		t.Fatalf("expected StateUnavailable on timeout, got %v", outcome.State())
	}
}

func TestAdvisoryProviderUnavailableEmptyBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// 0-byte body
	}))
	defer server.Close()

	p := NewAdvisoryProvider(
		WithAdvisoryBaseURL(server.URL),
	)

	outcome := p.Provide(context.Background(), Query{Package: "pkg", Version: "1.0.0"})
	if outcome.State() != StateUnavailable {
		t.Fatalf("expected StateUnavailable on 0-byte empty body, got %v", outcome.State())
	}
	sigs := outcome.Signals()
	if len(sigs) == 0 || sigs[0].Observation != "unavailable" {
		t.Fatalf("expected unavailable signal on empty body, got %+v", sigs)
	}
}

func TestAdvisoryProviderProvideBatch(t *testing.T) {
	var batchCalled atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/querybatch" {
			batchCalled.Store(true)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(osvBatchQueryResponse{
				Results: []osvQueryResponse{
					{
						Vulns: []osvVulnerability{
							{ID: "GHSA-1", Summary: "Vuln 1"},
						},
					},
					{
						Vulns: []osvVulnerability{},
					},
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	p := NewAdvisoryProvider(
		WithAdvisoryBaseURL(server.URL),
		WithAdvisoryClock(func() time.Time { return time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC) }),
	)

	queries := []Query{
		{Package: "pkg-a", Version: "1.0.0"},
		{Package: "pkg-b", Version: "2.0.0"},
	}

	outcomes := p.ProvideBatch(context.Background(), queries)
	if len(outcomes) != 2 {
		t.Fatalf("expected 2 batch outcomes, got %d", len(outcomes))
	}
	if !batchCalled.Load() {
		t.Fatal("expected /v1/querybatch endpoint to be called")
	}

	if outcomes[0].State() != StateAvailable || len(outcomes[0].Signals()) == 0 {
		t.Fatalf("unexpected outcome 0: %+v", outcomes[0])
	}
	if outcomes[0].Signals()[0].Observation != "above_threshold" {
		t.Fatalf("expected above_threshold for pkg-a, got %q", outcomes[0].Signals()[0].Observation)
	}

	if outcomes[1].State() != StateAvailable || len(outcomes[1].Signals()) == 0 {
		t.Fatalf("unexpected outcome 1: %+v", outcomes[1])
	}
	if outcomes[1].Signals()[0].Observation != "no_record_found" {
		t.Fatalf("expected no_record_found for pkg-b, got %q", outcomes[1].Signals()[0].Observation)
	}
}
