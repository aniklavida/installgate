package gateway

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sort"
	"testing"
	"time"

	"github.com/aniklavida/installgate/internal/evidence"
	"github.com/aniklavida/installgate/internal/explanation"
	"github.com/aniklavida/installgate/internal/verdict"
)

func TestCachedKnownGoodDecisionOverhead(t *testing.T) {
	// 1. Upstream registry server mock
	upstreamBody := []byte(`{"name":"cached-pkg","versions":{"1.0.0":{}}}`)
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(upstreamBody)
	}))
	defer upstreamServer.Close()

	// 2. Setup gateway with cache containing cached allow decision
	cache := evidence.NewMemoryCache()
	now := time.Now().UTC()
	pkg := "cached-pkg"
	version := "1.0.0"

	// Cache allow decision
	allowDecision := verdict.Decision{
		Verdict: verdict.Allow,
		Reasons: []verdict.Reason{
			{
				RuleID:  "core.cached-allow",
				Summary: "package allowed by cached known-good decision",
			},
		},
	}
	cache.PutCachedAllow(pkg, version, allowDecision, "snap-perf", now, now.Add(2*time.Hour), now.Add(24*time.Hour))

	evaluator := EvaluatorFunc(func(ctx context.Context, p, v string) (*explanation.DecisionDocument, error) {
		if p == pkg && v == version {
			if _, ok := cache.GetCachedAllow(p, v, time.Now()); ok {
				snap := evidence.NewSnapshot(p, v, nil, nil, time.Now())
				return explanation.NewDecisionDocument(p, v, allowDecision, snap)
			}
		}
		return nil, nil
	})

	handler, err := NewHandler(Config{
		UpstreamBaseURL: upstreamServer.URL,
		Evaluator:       evaluator,
		Cache:           cache,
	})
	if err != nil {
		t.Fatalf("NewHandler failed: %v", err)
	}

	gwServer := httptest.NewServer(handler)
	defer gwServer.Close()

	client := &http.Client{
		Transport: &http.Transport{
			MaxIdleConnsPerHost: 50,
			IdleConnTimeout:     90 * time.Second,
		},
		Timeout: 5 * time.Second,
	}

	// Warm up
	for i := 0; i < 20; i++ {
		resp, err := client.Get(gwServer.URL + "/" + pkg)
		if err != nil {
			t.Fatalf("warmup failed: %v", err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}

	// 3. Measure overhead over 500 iterations
	const iterations = 500
	overheads := make([]time.Duration, iterations)

	reqURL := gwServer.URL + "/" + pkg
	upstreamReqURL := upstreamServer.URL + "/" + pkg

	for i := 0; i < iterations; i++ {
		// Time direct upstream
		t0 := time.Now()
		uResp, err := client.Get(upstreamReqURL)
		if err != nil {
			t.Fatalf("direct upstream request failed: %v", err)
		}
		_, _ = io.Copy(io.Discard, uResp.Body)
		_ = uResp.Body.Close()
		directDuration := time.Since(t0)

		// Time gateway request
		t1 := time.Now()
		gResp, err := client.Get(reqURL)
		if err != nil {
			t.Fatalf("gateway request failed: %v", err)
		}
		_, _ = io.Copy(io.Discard, gResp.Body)
		_ = gResp.Body.Close()
		gwDuration := time.Since(t1)

		diff := gwDuration - directDuration
		if diff < 0 {
			diff = 0
		}
		overheads[i] = diff
	}

	// 4. Compute p95 overhead
	sort.Slice(overheads, func(i, j int) bool {
		return overheads[i] < overheads[j]
	})

	p95Idx := int(float64(iterations) * 0.95)
	p95Overhead := overheads[p95Idx]
	medianOverhead := overheads[iterations/2]
	p99Idx := int(float64(iterations) * 0.99)
	p99Overhead := overheads[p99Idx]

	machineName := fmt.Sprintf("%s/%s (%d CPUs)", runtime.GOOS, runtime.GOARCH, runtime.NumCPU())

	t.Logf("==================================================================")
	t.Logf("CACHED KNOWN-GOOD DECISION OVERHEAD MEASUREMENT")
	t.Logf("Machine:         %s", machineName)
	t.Logf("Iterations:      %d", iterations)
	t.Logf("Median Overhead: %v", medianOverhead)
	t.Logf("p95 Overhead:    %v", p95Overhead)
	t.Logf("p99 Overhead:    %v", p99Overhead)
	t.Logf("==================================================================")

	// Hard constraint: Cached known-good decisions should add no more than 50 ms p95 overhead
	maxAllowed := 50 * time.Millisecond
	if p95Overhead > maxAllowed {
		t.Fatalf("p95 overhead %v exceeds maximum allowed %v on %s", p95Overhead, maxAllowed, machineName)
	}
}
