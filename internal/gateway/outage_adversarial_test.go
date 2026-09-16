package gateway

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aniklavida/installgate/internal/evidence"
	"github.com/aniklavida/installgate/internal/explanation"
	"github.com/aniklavida/installgate/internal/policy"
	"github.com/aniklavida/installgate/internal/quarantine"
	"github.com/aniklavida/installgate/internal/verdict"
)

func createValidTestTarball(t *testing.T, pkg, ver string) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	pkgJSON, _ := json.Marshal(map[string]interface{}{
		"name":    pkg,
		"version": ver,
	})
	_ = tw.WriteHeader(&tar.Header{
		Name:     "package/package.json",
		Mode:     0o644,
		Size:     int64(len(pkgJSON)),
		Typeflag: tar.TypeReg,
	})
	_, _ = tw.Write(pkgJSON)
	_ = tw.Close()
	_ = gw.Close()

	tarBytes := buf.Bytes()
	h := sha512.Sum512(tarBytes)
	integrity := "sha512-" + base64.StdEncoding.EncodeToString(h[:])
	return tarBytes, integrity
}

// TestEmptyAdvisoryResponseCannotProduceCleanAllow_Gateway asserts that an advisory provider
// answering 200 OK with [] can NEVER produce a clean allow at the gateway surface, under any
// policy profile or cache condition, and that the degraded flag survives into both rendered explanations.
func TestEmptyAdvisoryResponseCannotProduceCleanAllow_Gateway(t *testing.T) {
	now := time.Date(2026, 9, 15, 14, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	tarballBytes, integrity := createValidTestTarball(t, "empty-advisory-pkg", "1.0.0")

	packumentJSON := fmt.Sprintf(`{
		"name": "empty-advisory-pkg",
		"time": {
			"created": "%s",
			"1.0.0": "%s"
		},
		"versions": {
			"1.0.0": {
				"name": "empty-advisory-pkg",
				"version": "1.0.0",
				"dist": {
					"tarball": "https://registry.npmjs.org/empty-advisory-pkg/-/empty-advisory-pkg-1.0.0.tgz",
					"integrity": "%s"
				}
			}
		}
	}`, now.Add(-30*24*time.Hour).Format(time.RFC3339), now.Add(-30*24*time.Hour).Format(time.RFC3339), integrity)

	// 1. Upstream npm registry
	regServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/empty-advisory-pkg":
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(packumentJSON))
		case "/empty-advisory-pkg/-/empty-advisory-pkg-1.0.0.tgz":
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(tarballBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer regServer.Close()

	// 2. Advisory provider answering HTTP 200 OK with "[]" (the primary failure mode)
	advisoryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("[]"))
	}))
	defer advisoryServer.Close()

	scenarios := []struct {
		name              string
		profile           policy.Profile
		withFreshCache    bool
		expectedStatus    int
		expectedVerdict   verdict.Kind
		expectedRuleID    string
		allowPayloadCheck bool
	}{
		{
			name:            "NoCache_BalancedProfile_BlocksWithApprovalRequired",
			profile:         policy.Balanced,
			withFreshCache:  false,
			expectedStatus:  http.StatusForbidden,
			expectedVerdict: verdict.ApprovalRequired,
			expectedRuleID:  "availability.no-cache",
		},
		{
			name:            "NoCache_StrictProfile_BlocksWithBlock",
			profile:         policy.Strict,
			withFreshCache:  false,
			expectedStatus:  http.StatusForbidden,
			expectedVerdict: verdict.Block,
			expectedRuleID:  "availability.strict",
		},
		{
			name:              "FreshCache_BalancedProfile_AllowsWithStaleWarningDegraded",
			profile:           policy.Balanced,
			withFreshCache:    true,
			expectedStatus:    http.StatusOK,
			expectedVerdict:   verdict.Allow,
			expectedRuleID:    "availability.fresh-cache",
			allowPayloadCheck: true,
		},
		{
			name:            "FreshCache_StrictProfile_BlocksWithApprovalRequired",
			profile:         policy.Strict,
			withFreshCache:  true,
			expectedStatus:  http.StatusForbidden,
			expectedVerdict: verdict.ApprovalRequired,
			expectedRuleID:  "availability.fresh-cache",
		},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			tempDir := t.TempDir()
			decStore, err := explanation.NewFileStore(filepath.Join(tempDir, "decisions"))
			if err != nil {
				t.Fatalf("NewFileStore failed: %v", err)
			}

			metaStore := quarantine.NewMemoryMetadataStore()
			blobStore, _ := quarantine.NewDiskBlobStore(filepath.Join(tempDir, "quarantine"), quarantine.DiskBudget{MaxBytes: 10 * 1024 * 1024}, metaStore)
			qMgr, _ := quarantine.NewManager(quarantine.Config{
				Store:    blobStore,
				Metadata: metaStore,
				Limits:   quarantine.DefaultArchiveLimits(),
				Clock:    clock,
			})

			cache := evidence.NewMemoryCache()
			if sc.withFreshCache {
				// Seed cache with a fresh cached allow
				cache.PutCachedAllow(
					"empty-advisory-pkg",
					"1.0.0",
					verdict.Decision{
						Verdict: verdict.Allow,
						Reasons: []verdict.Reason{{RuleID: "core.policy-satisfied"}},
					},
					"sha256:dummy",
					now.Add(-1*time.Hour),
					now.Add(23*time.Hour),
					now.Add(48*time.Hour),
				)
			}

			advisoryProv := evidence.NewAdvisoryProvider(
				evidence.WithAdvisoryBaseURL(advisoryServer.URL),
				evidence.WithAdvisoryClock(clock),
			)
			historyProv := evidence.NewHistoryProvider(
				evidence.WithHistoryRegistryURL(regServer.URL),
				evidence.WithHistoryClock(clock),
			)

			assembler := evidence.NewAssembler(
				evidence.WithClock(clock),
				evidence.WithCache(cache),
				evidence.WithFreshnessPolicy(evidence.DefaultFreshnessPolicy()),
				evidence.WithProviders(advisoryProv, historyProv),
			)

			pol := &policy.Policy{
				Version:                policy.CurrentPolicyVersion,
				Profile:                sc.profile,
				VulnerabilityThreshold: policy.SeverityHigh,
			}

			engine := NewEngine(EngineConfig{
				Policy:    pol,
				Assembler: assembler,
				Actor:     "gateway-test",
			})

			handler, err := NewHandler(Config{
				UpstreamBaseURL: regServer.URL,
				Transport:       regServer.Client().Transport,
				Evaluator:       engine,
				DecisionStore:   decStore,
				Quarantine:      qMgr,
				Cache:           cache,
			})
			if err != nil {
				t.Fatalf("NewHandler failed: %v", err)
			}

			gwServer := httptest.NewServer(handler)
			defer gwServer.Close()

			// Pre-fetch metadata so integrity is indexed
			metaResp, err := http.Get(gwServer.URL + "/empty-advisory-pkg")
			if err != nil {
				t.Fatalf("GET metadata failed: %v", err)
			}
			metaResp.Body.Close()

			// Request tarball
			tarResp, err := http.Get(gwServer.URL + "/empty-advisory-pkg/-/empty-advisory-pkg-1.0.0.tgz")
			if err != nil {
				t.Fatalf("GET tarball failed: %v", err)
			}
			defer tarResp.Body.Close()

			if tarResp.StatusCode != sc.expectedStatus {
				t.Fatalf("expected HTTP status %d, got %d", sc.expectedStatus, tarResp.StatusCode)
			}

			// Core safety assertion:
			// A clean allow is verdict == Allow with Degraded == false and rule == core.policy-satisfied.
			// Proving that an empty advisory response CAN NEVER produce a clean allow.
			var doc *explanation.DecisionDocument

			if sc.expectedStatus == http.StatusForbidden {
				decID := tarResp.Header.Get("X-InstallGate-Decision")
				if decID == "" {
					t.Fatal("expected X-InstallGate-Decision header on blocked response")
				}
				doc, err = decStore.Get(decID)
				if err != nil {
					t.Fatalf("failed retrieving decision doc %q: %v", decID, err)
				}
			} else {
				// Status 200 OK: inspect decision from engine
				doc, err = engine.Evaluate(context.Background(), "empty-advisory-pkg", "1.0.0")
				if err != nil {
					t.Fatalf("engine.Evaluate failed: %v", err)
				}
			}

			if doc == nil {
				t.Fatal("decision document is nil")
			}

			// PROVE: Never a clean allow!
			if doc.Verdict == verdict.Allow && !doc.Degraded {
				t.Fatalf("SECURITY FAILURE: empty advisory response produced a clean allow! doc: %+v", doc)
			}

			// Check expected verdict
			if doc.Verdict != sc.expectedVerdict {
				t.Fatalf("expected verdict %q, got %q", sc.expectedVerdict, doc.Verdict)
			}

			// Check rule ID
			if len(doc.Reasons) == 0 || doc.Reasons[0].RuleID != sc.expectedRuleID {
				t.Fatalf("expected rule ID %q, got %+v", sc.expectedRuleID, doc.Reasons)
			}

			// Check degraded flag: MUST BE TRUE on every degraded path
			if !doc.Degraded {
				t.Fatalf("expected Degraded=true during evidence outage, got false")
			}

			// PROVE: Degraded flag survives into BOTH renderings!
			// 1. JSON rendering
			jsonBytes, err := explanation.RenderJSON(doc)
			if err != nil {
				t.Fatalf("RenderJSON failed: %v", err)
			}
			var parsedJSON map[string]interface{}
			if err := json.Unmarshal(jsonBytes, &parsedJSON); err != nil {
				t.Fatalf("unmarshal rendered JSON failed: %v", err)
			}
			if degVal, ok := parsedJSON["degraded"].(bool); !ok || !degVal {
				t.Fatalf("JSON rendering failed to preserve degraded=true: %s", string(jsonBytes))
			}

			// 2. Human rendering
			humanStr := explanation.RenderHuman(doc)
			if !strings.HasPrefix(humanStr, "DEGRADED DECISION:") {
				t.Fatalf("Human rendering failed to state DEGRADED DECISION on first line:\n%s", humanStr)
			}
		})
	}
}
