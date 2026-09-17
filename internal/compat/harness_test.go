package compat

import (
	"bytes"
	"io"
	"net/http"
	"testing"
)

func TestHarness_GatewayPassThroughAndQuarantine(t *testing.T) {
	h := NewTestHarness(t)

	// 1. Fetch metadata through gateway
	metaURL := h.GatewayURL() + "/fixture-unscoped"
	resp, err := http.Get(metaURL)
	if err != nil {
		t.Fatalf("GET /fixture-unscoped failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed reading metadata body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200 OK, got %d: %s", resp.StatusCode, string(body))
	}
	if !bytes.Contains(body, []byte("fixture-unscoped")) {
		t.Fatalf("metadata response does not contain package name: %s", string(body))
	}

	// 2. Fetch tarball through gateway (runs through quarantine, verifies integrity, and releases)
	tarballURL := h.GatewayURL() + "/fixture-unscoped/-/fixture-unscoped-1.0.0.tgz"
	tarResp, err := http.Get(tarballURL)
	if err != nil {
		t.Fatalf("GET tarball failed: %v", err)
	}
	defer tarResp.Body.Close()

	if tarResp.StatusCode != http.StatusOK {
		t.Fatalf("expected tarball status 200 OK, got %d", tarResp.StatusCode)
	}

	tarBytes, err := io.ReadAll(tarResp.Body)
	if err != nil {
		t.Fatalf("failed reading tarball body: %v", err)
	}

	expectedBytes := h.Packages["fixture-unscoped"].TarballBytes
	if !bytes.Equal(tarBytes, expectedBytes) {
		t.Fatalf("delivered tarball bytes differ from original fixture bytes")
	}
}

func TestHarness_AbbreviatedPackumentHeader(t *testing.T) {
	h := NewTestHarness(t)

	client := &http.Client{}
	req, err := http.NewRequest(http.MethodGet, h.GatewayURL()+"/fixture-unscoped", nil)
	if err != nil {
		t.Fatalf("failed creating request: %v", err)
	}
	req.Header.Set("Accept", "application/vnd.npm.install-v1+json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET abbreviated packument failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200 OK, got %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if !bytes.Contains([]byte(contentType), []byte("application/vnd.npm.install-v1+json")) {
		t.Errorf("expected Content-Type to contain abbreviated packument mime, got %q", contentType)
	}

	// Verify upstream captured the Accept header
	captured := h.CapturedHeaders()
	if len(captured) == 0 {
		t.Fatal("no captured headers recorded at upstream")
	}

	foundAccept := false
	for _, cap := range captured {
		if bytes.Contains([]byte(cap.Accept), []byte("application/vnd.npm.install-v1+json")) {
			foundAccept = true
			break
		}
	}
	if !foundAccept {
		t.Errorf("upstream did not receive expected Accept header with abbreviated packument format")
	}
}

func TestHarness_ConditionalRequest304NotModified(t *testing.T) {
	h := NewTestHarness(t)

	// Initial request to get ETag
	resp, err := http.Get(h.GatewayURL() + "/fixture-unscoped")
	if err != nil {
		t.Fatalf("GET metadata failed: %v", err)
	}
	resp.Body.Close()

	etag := resp.Header.Get("ETag")
	if etag == "" {
		t.Fatal("expected ETag header on initial response")
	}

	// Conditional request with If-None-Match
	client := &http.Client{}
	req, err := http.NewRequest(http.MethodGet, h.GatewayURL()+"/fixture-unscoped", nil)
	if err != nil {
		t.Fatalf("failed creating request: %v", err)
	}
	req.Header.Set("If-None-Match", etag)

	condResp, err := client.Do(req)
	if err != nil {
		t.Fatalf("conditional GET failed: %v", err)
	}
	defer condResp.Body.Close()

	if condResp.StatusCode != http.StatusNotModified {
		t.Fatalf("expected status 304 Not Modified, got %d", condResp.StatusCode)
	}
}

func TestHarness_CorruptedTarballRejectedByGatewayQuarantine(t *testing.T) {
	h := NewTestHarness(t)

	// Fetch metadata first so gateway integrity index knows the expected checksum
	metaResp, err := http.Get(h.GatewayURL() + "/fixture-tampered")
	if err != nil {
		t.Fatalf("GET metadata failed: %v", err)
	}
	metaResp.Body.Close()

	// Corrupt the upstream tarball
	h.SetCorrupted("fixture-tampered", true)

	// Request the tarball: gateway quarantine's first integrity check MUST fail and block
	tarResp, err := http.Get(h.GatewayURL() + "/fixture-tampered/-/fixture-tampered-1.0.0.tgz")
	if err != nil {
		t.Fatalf("GET tarball failed: %v", err)
	}
	defer tarResp.Body.Close()

	if tarResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for corrupted tarball, got %d", tarResp.StatusCode)
	}

	decID := tarResp.Header.Get("X-InstallGate-Decision")
	if decID == "" {
		t.Error("expected X-InstallGate-Decision header on blocked corrupted tarball response")
	}

	// Restore uncorrupted tarball and confirm gateway delivers cleanly
	h.SetCorrupted("fixture-tampered", false)
	tarResp2, err := http.Get(h.GatewayURL() + "/fixture-tampered/-/fixture-tampered-1.0.0.tgz")
	if err != nil {
		t.Fatalf("GET restored tarball failed: %v", err)
	}
	defer tarResp2.Body.Close()

	if tarResp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK after restoring tarball, got %d", tarResp2.StatusCode)
	}
}

func TestHarness_ScopedPackageRoutes(t *testing.T) {
	h := NewTestHarness(t)

	// 1. Scoped metadata
	scopedMetaURL := h.GatewayURL() + "/@testscope/fixture-scoped"
	resp, err := http.Get(scopedMetaURL)
	if err != nil {
		t.Fatalf("GET scoped metadata failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200 OK for scoped package, got %d", resp.StatusCode)
	}

	// 2. Scoped tarball
	scopedTarURL := h.GatewayURL() + "/@testscope/fixture-scoped/-/fixture-scoped-1.0.0.tgz"
	tarResp, err := http.Get(scopedTarURL)
	if err != nil {
		t.Fatalf("GET scoped tarball failed: %v", err)
	}
	defer tarResp.Body.Close()

	if tarResp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200 OK for scoped tarball, got %d", tarResp.StatusCode)
	}
}
