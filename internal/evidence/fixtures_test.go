package evidence

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aniklavida/installgate/internal/verdict"
)

// HTTPAdvisoryProvider is an evidence provider fixture that queries an HTTP advisory service.
type HTTPAdvisoryProvider struct {
	baseURL string
	client  *http.Client
	clock   func() time.Time
}

type advisoryResponse struct {
	Status     string            `json:"status,omitempty"`
	Advisories []advisoryFinding `json:"advisories"`
}

type advisoryFinding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
}

func (p *HTTPAdvisoryProvider) Name() string {
	return "test_http_advisories"
}

func (p *HTTPAdvisoryProvider) Kind() string {
	return KindVulnerability
}

func (p *HTTPAdvisoryProvider) Provide(ctx context.Context, q Query) Outcome {
	now := time.Now()
	if p.clock != nil {
		now = p.clock()
	}

	url := fmt.Sprintf("%s/advisories?pkg=%s&ver=%s", p.baseURL, q.Package, q.Version)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return NewUnavailableOutcome(p.Kind(), p.Name(), err, now)
	}

	client := p.client
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		return NewUnavailableOutcome(p.Kind(), p.Name(), err, now)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return NewUnavailableOutcome(p.Kind(), p.Name(), fmt.Errorf("upstream returned HTTP %d", resp.StatusCode), now)
	}

	// Read full body; handles mid-stream timeouts and empty bodies
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return NewUnavailableOutcome(p.Kind(), p.Name(), fmt.Errorf("read error: %w", err), now)
	}

	if len(bodyBytes) == 0 {
		return NewUnavailableOutcome(p.Kind(), p.Name(), errors.New("unexpected empty body: expected JSON advisory payload"), now)
	}

	var parsed advisoryResponse
	if err := json.Unmarshal(bodyBytes, &parsed); err != nil {
		return NewUnavailableOutcome(p.Kind(), p.Name(), fmt.Errorf("invalid json payload: %w", err), now)
	}

	freshUntil := now.Add(1 * time.Hour)

	// Check if upstream signaled degraded service
	if parsed.Status == "degraded" {
		var sigs []verdict.Signal
		for _, adv := range parsed.Advisories {
			sigs = append(sigs, verdict.Signal{
				Kind:        p.Kind(),
				Source:      p.Name(),
				Observation: adv.Severity,
				Confidence:  ConfidenceLow,
				RetrievedAt: now,
				FreshUntil:  freshUntil,
			})
		}
		if len(sigs) == 0 {
			sigs = append(sigs, verdict.Signal{
				Kind:        p.Kind(),
				Source:      p.Name(),
				Observation: "none",
				Confidence:  ConfidenceLow,
				RetrievedAt: now,
				FreshUntil:  freshUntil,
			})
		}
		return NewDegradedOutcome(p.Kind(), p.Name(), sigs, now, freshUntil, "upstream advisory database operating in degraded mode")
	}

	// Check if response header signaled stale data
	if warning := resp.Header.Get("Warning"); strings.Contains(warning, "110") {
		var sigs []verdict.Signal
		for _, adv := range parsed.Advisories {
			sigs = append(sigs, verdict.Signal{
				Kind:        p.Kind(),
				Source:      p.Name(),
				Observation: adv.Severity,
				Confidence:  ConfidenceMedium,
				RetrievedAt: now,
				FreshUntil:  now, // stale
			})
		}
		if len(sigs) == 0 {
			sigs = append(sigs, verdict.Signal{
				Kind:        p.Kind(),
				Source:      p.Name(),
				Observation: "none",
				Confidence:  ConfidenceMedium,
				RetrievedAt: now,
				FreshUntil:  now,
			})
		}
		return NewStaleOutcome(p.Kind(), p.Name(), sigs, now, now, "upstream returned stale advisory cache")
	}

	// Available state: findings or verified clean (well-formed empty body)
	var sigs []verdict.Signal
	if len(parsed.Advisories) > 0 {
		for _, adv := range parsed.Advisories {
			obs := "above_threshold"
			if adv.Severity == "low" {
				obs = "below_threshold"
			}
			sigs = append(sigs, verdict.Signal{
				Kind:        p.Kind(),
				Source:      p.Name(),
				Observation: obs,
				Confidence:  ConfidenceHigh,
				RetrievedAt: now,
				FreshUntil:  freshUntil,
			})
		}
	} else {
		// Well-formed empty body explicitly records verified absence of vulnerabilities
		sigs = append(sigs, verdict.Signal{
			Kind:        p.Kind(),
			Source:      p.Name(),
			Observation: "none",
			Confidence:  ConfidenceHigh,
			RetrievedAt: now,
			FreshUntil:  freshUntil,
		})
	}

	return NewAvailableOutcome(p.Kind(), p.Name(), sigs, now, freshUntil)
}

func TestFixtureStateAvailableWithFindings(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"advisories":[{"id":"CVE-2026-1","severity":"critical"}]}`))
	}))
	defer ts.Close()

	provider := &HTTPAdvisoryProvider{baseURL: ts.URL}
	outcome := provider.Provide(context.Background(), Query{Package: "vulnerable-lib", Version: "1.0.0"})

	if outcome.State() != StateAvailable {
		t.Fatalf("expected StateAvailable, got %v", outcome.State())
	}
	sigs := outcome.Signals()
	if len(sigs) != 1 || sigs[0].Observation != "above_threshold" {
		t.Fatalf("unexpected signals: %+v", sigs)
	}
}

func TestFixtureStateAvailableWellFormedEmptyBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Well-formed JSON payload with empty advisories list
		_, _ = w.Write([]byte(`{"advisories":[]}`))
	}))
	defer ts.Close()

	provider := &HTTPAdvisoryProvider{baseURL: ts.URL}
	outcome := provider.Provide(context.Background(), Query{Package: "safe-lib", Version: "1.0.0"})

	if outcome.State() != StateAvailable {
		t.Fatalf("expected StateAvailable, got %v", outcome.State())
	}
	sigs := outcome.Signals()
	if len(sigs) != 1 {
		t.Fatalf("expected 1 explicit observation, got %d", len(sigs))
	}
	if sigs[0].Observation != "none" {
		t.Fatalf("expected observation 'none', got %q", sigs[0].Observation)
	}
	if sigs[0].Confidence != ConfidenceHigh {
		t.Fatalf("expected high confidence, got %q", sigs[0].Confidence)
	}
}

func TestFixtureStateStale(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Warning", `110 - "Response is Stale"`)
		_, _ = w.Write([]byte(`{"advisories":[]}`))
	}))
	defer ts.Close()

	provider := &HTTPAdvisoryProvider{baseURL: ts.URL}
	outcome := provider.Provide(context.Background(), Query{Package: "pkg", Version: "1.0.0"})

	if outcome.State() != StateStale {
		t.Fatalf("expected StateStale, got %v", outcome.State())
	}
	if !outcome.IsStale() {
		t.Fatal("IsStale() should return true")
	}
	if outcome.Reason() == "" {
		t.Fatal("stale outcome should have explanatory reason")
	}
}

func TestFixtureStateDegraded(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"degraded","advisories":[]}`))
	}))
	defer ts.Close()

	provider := &HTTPAdvisoryProvider{baseURL: ts.URL}
	outcome := provider.Provide(context.Background(), Query{Package: "pkg", Version: "1.0.0"})

	if outcome.State() != StateDegraded {
		t.Fatalf("expected StateDegraded, got %v", outcome.State())
	}
	if !outcome.IsDegraded() {
		t.Fatal("IsDegraded() should return true")
	}
}

func TestFixtureStateUnavailableTimeoutMidResponse(t *testing.T) {
	// Server writes headers, partial body chunk, then stalls until client deadline
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			_, _ = w.Write([]byte(`{"advisories":[`))
			f.Flush()
		}
		// Stall indefinitely to trigger client context deadline
		time.Sleep(2 * time.Second)
	}))
	defer ts.Close()

	provider := &HTTPAdvisoryProvider{baseURL: ts.URL}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	outcome := provider.Provide(ctx, Query{Package: "pkg", Version: "1.0.0"})

	if outcome.State() != StateUnavailable {
		t.Fatalf("expected StateUnavailable on mid-stream timeout, got %v", outcome.State())
	}
	if !outcome.IsUnavailable() {
		t.Fatal("IsUnavailable() should return true")
	}
	if outcome.Err() == nil {
		t.Fatal("unavailable outcome must report error")
	}

	// CRITICAL: Ensure signals() returns explicit unavailable record, NEVER empty or "none"
	sigs := outcome.Signals()
	if len(sigs) == 0 {
		t.Fatal("signals() must not be empty on unavailable failure")
	}
	if sigs[0].Observation != "unavailable" {
		t.Fatalf("observation must be 'unavailable', got %q", sigs[0].Observation)
	}
	if sigs[0].Confidence != ConfidenceNone {
		t.Fatalf("confidence must be 'none', got %q", sigs[0].Confidence)
	}
}

func TestFixtureStateUnavailableUnexpectedEmptyBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Server returns 200 OK with 0-byte body
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	provider := &HTTPAdvisoryProvider{baseURL: ts.URL}
	outcome := provider.Provide(context.Background(), Query{Package: "pkg", Version: "1.0.0"})

	if outcome.State() != StateUnavailable {
		t.Fatalf("expected StateUnavailable on 0-byte empty body, got %v", outcome.State())
	}
	if outcome.Err() == nil {
		t.Fatal("unexpected empty body must produce an error")
	}
	sigs := outcome.Signals()
	if len(sigs) == 0 || sigs[0].Observation != "unavailable" {
		t.Fatalf("unexpected signals: %+v", sigs)
	}
}

func TestFixtureStateUnavailableHttp500(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer ts.Close()

	provider := &HTTPAdvisoryProvider{baseURL: ts.URL}
	outcome := provider.Provide(context.Background(), Query{Package: "pkg", Version: "1.0.0"})

	if outcome.State() != StateUnavailable {
		t.Fatalf("expected StateUnavailable on 500 error, got %v", outcome.State())
	}
	sigs := outcome.Signals()
	if len(sigs) == 0 || sigs[0].Observation != "unavailable" {
		t.Fatalf("unexpected signals: %+v", sigs)
	}
}
