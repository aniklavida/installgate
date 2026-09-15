package gateway

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aniklavida/installgate/internal/evidence"
)

var accusatoryTerms = []string{
	"malicious",
	"attack",
	"violation",
	"threat",
	"security finding",
	"security policy",
	"blocked",
	"forbidden",
	"quarantine",
	"suspicious",
}

func assertNonAccusatory(t *testing.T, text string) {
	t.Helper()
	lower := strings.ToLower(text)
	for _, term := range accusatoryTerms {
		if strings.Contains(lower, term) {
			t.Errorf("text contains accusatory term %q: %s", term, text)
		}
	}
}

func makeGzip(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		t.Fatalf("gzip write failed: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("gzip close failed: %v", err)
	}
	return buf.Bytes()
}

func TestMetadataPassThrough_Unscoped(t *testing.T) {
	upstreamBody := []byte(`{"name":"lodash","dist-tags":{"latest":"4.17.21"},"versions":{"4.17.21":{"name":"lodash","version":"4.17.21"}}}`)
	upstreamETag := `W/"123456789"`
	upstreamLastMod := "Wed, 21 Oct 2025 07:28:00 GMT"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/lodash" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("ETag", upstreamETag)
		w.Header().Set("Last-Modified", upstreamLastMod)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(upstreamBody)
	}))
	defer upstream.Close()

	handler, err := NewHandler(Config{
		UpstreamBaseURL: upstream.URL,
		Transport:       upstream.Client().Transport,
	})
	if err != nil {
		t.Fatalf("NewHandler() failed: %v", err)
	}
	gwServer := httptest.NewServer(handler)
	defer gwServer.Close()

	resp, err := http.Get(gwServer.URL + "/lodash")
	if err != nil {
		t.Fatalf("GET /lodash failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("ETag"); got != upstreamETag {
		t.Errorf("got ETag %q, want %q", got, upstreamETag)
	}
	if got := resp.Header.Get("Last-Modified"); got != upstreamLastMod {
		t.Errorf("got Last-Modified %q, want %q", got, upstreamLastMod)
	}
	if got := resp.Header.Get("Content-Type"); !strings.Contains(got, "application/json") {
		t.Errorf("got Content-Type %q, want application/json", got)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}
	if !bytes.Equal(body, upstreamBody) {
		t.Errorf("metadata body not byte-identical:\ngot:  %s\nwant: %s", body, upstreamBody)
	}
}

func TestMetadataPassThrough_ScopedBothSpellings(t *testing.T) {
	upstreamBody := []byte(`{"name":"@scope/pkg","dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{"name":"@scope/pkg","version":"1.0.0"}}}`)
	upstreamETag := `"scoped-etag-999"`
	upstreamLastMod := "Thu, 22 Oct 2025 10:00:00 GMT"

	var upstreamPaths []string
	var mu sync.Mutex

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		upstreamPaths = append(upstreamPaths, r.URL.EscapedPath())
		mu.Unlock()

		// npm registry expects @scope%2Fpkg
		if r.URL.EscapedPath() != "/@scope%2Fpkg" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", upstreamETag)
		w.Header().Set("Last-Modified", upstreamLastMod)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(upstreamBody)
	}))
	defer upstream.Close()

	handler, err := NewHandler(Config{
		UpstreamBaseURL: upstream.URL,
		Transport:       upstream.Client().Transport,
	})
	if err != nil {
		t.Fatalf("NewHandler() failed: %v", err)
	}
	gwServer := httptest.NewServer(handler)
	defer gwServer.Close()

	spellings := []string{
		"/@scope%2Fpkg", // URL-encoded
		"/@scope/pkg",   // Decoded
	}

	for _, path := range spellings {
		t.Run("path_"+path, func(t *testing.T) {
			resp, err := http.Get(gwServer.URL + path)
			if err != nil {
				t.Fatalf("GET %s failed: %v", path, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("got status %d, want 200", resp.StatusCode)
			}
			if got := resp.Header.Get("ETag"); got != upstreamETag {
				t.Errorf("got ETag %q, want %q", got, upstreamETag)
			}
			if got := resp.Header.Get("Last-Modified"); got != upstreamLastMod {
				t.Errorf("got Last-Modified %q, want %q", got, upstreamLastMod)
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read body failed: %v", err)
			}
			if !bytes.Equal(body, upstreamBody) {
				t.Errorf("body not byte-identical")
			}
		})
	}

	mu.Lock()
	defer mu.Unlock()
	if len(upstreamPaths) != 2 {
		t.Fatalf("expected 2 upstream calls, got %d", len(upstreamPaths))
	}
	for i, p := range upstreamPaths {
		if p != "/@scope%2Fpkg" {
			t.Errorf("upstream call %d received path %q, want %q", i, p, "/@scope%2Fpkg")
		}
	}
}

func TestMetadataPassThrough_GzipContentEncoding(t *testing.T) {
	rawJSON := []byte(`{"name":"lodash","description":"raw uncompressed payload"}`)
	gzippedBytes := makeGzip(t, rawJSON)
	upstreamETag := `"gzip-etag-123"`

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("ETag", upstreamETag)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(gzippedBytes)
	}))
	defer upstream.Close()

	handler, err := NewHandler(Config{
		UpstreamBaseURL: upstream.URL,
		Transport:       upstream.Client().Transport,
	})
	if err != nil {
		t.Fatalf("NewHandler() failed: %v", err)
	}
	gwServer := httptest.NewServer(handler)
	defer gwServer.Close()

	// Use transport with DisableCompression to inspect the exact wire bytes received
	client := &http.Client{
		Transport: &http.Transport{
			DisableCompression: true,
		},
	}

	req, _ := http.NewRequest(http.MethodGet, gwServer.URL+"/lodash", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /lodash failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Encoding"); got != "gzip" {
		t.Errorf("got Content-Encoding %q, want gzip", got)
	}
	if got := resp.Header.Get("ETag"); got != upstreamETag {
		t.Errorf("got ETag %q, want %q", got, upstreamETag)
	}

	receivedBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body failed: %v", err)
	}
	if !bytes.Equal(receivedBytes, gzippedBytes) {
		t.Fatalf("delivered gzip bytes not byte-identical to upstream")
	}

	// Decompress and verify content
	gr, err := gzip.NewReader(bytes.NewReader(receivedBytes))
	if err != nil {
		t.Fatalf("gzip.NewReader failed: %v", err)
	}
	defer gr.Close()
	decompressed, err := io.ReadAll(gr)
	if err != nil {
		t.Fatalf("failed reading decompressed data: %v", err)
	}
	if !bytes.Equal(decompressed, rawJSON) {
		t.Errorf("decompressed JSON mismatch:\ngot:  %s\nwant: %s", decompressed, rawJSON)
	}
}

func TestMetadataPassThrough_AbbreviatedPackumentContentNegotiation(t *testing.T) {
	abbreviatedJSON := []byte(`{"name":"lodash","modified":"2025-01-01T00:00:00.000Z","dist-tags":{"latest":"4.17.21"},"versions":{"4.17.21":{}}}`)
	fullJSON := []byte(`{"name":"lodash","_id":"lodash","readme":"Full README text"}`)

	corgiAccept := "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*"

	var receivedAccept string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAccept = r.Header.Get("Accept")
		if strings.Contains(receivedAccept, "application/vnd.npm.install-v1+json") {
			w.Header().Set("Content-Type", "application/vnd.npm.install-v1+json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(abbreviatedJSON)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fullJSON)
	}))
	defer upstream.Close()

	handler, err := NewHandler(Config{
		UpstreamBaseURL: upstream.URL,
		Transport:       upstream.Client().Transport,
	})
	if err != nil {
		t.Fatalf("NewHandler() failed: %v", err)
	}
	gwServer := httptest.NewServer(handler)
	defer gwServer.Close()

	req, _ := http.NewRequest(http.MethodGet, gwServer.URL+"/lodash", nil)
	req.Header.Set("Accept", corgiAccept)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/vnd.npm.install-v1+json" {
		t.Errorf("got Content-Type %q, want application/vnd.npm.install-v1+json", got)
	}
	if receivedAccept != corgiAccept {
		t.Errorf("upstream received Accept %q, want %q", receivedAccept, corgiAccept)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed reading body: %v", err)
	}
	if !bytes.Equal(body, abbreviatedJSON) {
		t.Errorf("body not byte-identical to abbreviated packument")
	}
}

func TestConditionalRequest_304NotModified(t *testing.T) {
	etag := `"v1.2.3-hash"`
	lastMod := "Mon, 10 Nov 2025 12:00:00 GMT"

	var receivedIfNoneMatch, receivedIfModifiedSince string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedIfNoneMatch = r.Header.Get("If-None-Match")
		receivedIfModifiedSince = r.Header.Get("If-Modified-Since")

		if receivedIfNoneMatch == etag {
			w.Header().Set("ETag", etag)
			w.Header().Set("Last-Modified", lastMod)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		w.Header().Set("Last-Modified", lastMod)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"name":"lodash"}`))
	}))
	defer upstream.Close()

	handler, err := NewHandler(Config{
		UpstreamBaseURL: upstream.URL,
		Transport:       upstream.Client().Transport,
	})
	if err != nil {
		t.Fatalf("NewHandler() failed: %v", err)
	}
	gwServer := httptest.NewServer(handler)
	defer gwServer.Close()

	req, _ := http.NewRequest(http.MethodGet, gwServer.URL+"/lodash", nil)
	req.Header.Set("If-None-Match", etag)
	req.Header.Set("If-Modified-Since", lastMod)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("conditional request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotModified {
		t.Fatalf("got status %d, want 304 Not Modified", resp.StatusCode)
	}
	if got := resp.Header.Get("ETag"); got != etag {
		t.Errorf("got ETag %q, want %q", got, etag)
	}
	if receivedIfNoneMatch != etag {
		t.Errorf("upstream received If-None-Match %q, want %q", receivedIfNoneMatch, etag)
	}
	if receivedIfModifiedSince != lastMod {
		t.Errorf("upstream received If-Modified-Since %q, want %q", receivedIfModifiedSince, lastMod)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body failed: %v", err)
	}
	if len(body) != 0 {
		t.Errorf("expected empty body for 304, got %d bytes", len(body))
	}
}

func TestTarballPassThrough_AndIntegrityVerification(t *testing.T) {
	// Generate realistic tarball content
	tarballBytes := makeGzip(t, []byte("fake tar content: package/package.json and index.js"))

	// Compute declared integrity metadata
	h512 := sha512.Sum512(tarballBytes)
	declaredIntegrity := "sha512-" + base64.StdEncoding.EncodeToString(h512[:])

	h1 := sha1.Sum(tarballBytes)
	declaredShasum := hex.EncodeToString(h1[:])

	packumentJSON := fmt.Sprintf(`{
		"name": "lodash",
		"versions": {
			"4.17.21": {
				"name": "lodash",
				"version": "4.17.21",
				"dist": {
					"tarball": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
					"shasum": "%s",
					"integrity": "%s"
				}
			}
		}
	}`, declaredShasum, declaredIntegrity)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/lodash":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(packumentJSON))
		case "/lodash/-/lodash-4.17.21.tgz", "/@scope/pkg/-/pkg-1.2.3.tgz":
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(tarballBytes)))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(tarballBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	handler, err := NewHandler(Config{
		UpstreamBaseURL: upstream.URL,
		Transport:       upstream.Client().Transport,
	})
	if err != nil {
		t.Fatalf("NewHandler() failed: %v", err)
	}
	gwServer := httptest.NewServer(handler)
	defer gwServer.Close()

	// 1. Fetch metadata and extract integrity and shasum
	metaResp, err := http.Get(gwServer.URL + "/lodash")
	if err != nil {
		t.Fatalf("GET /lodash failed: %v", err)
	}
	defer metaResp.Body.Close()

	var meta struct {
		Versions map[string]struct {
			Dist struct {
				Integrity string `json:"integrity"`
				Shasum    string `json:"shasum"`
			} `json:"dist"`
		} `json:"versions"`
	}
	if err := json.NewDecoder(metaResp.Body).Decode(&meta); err != nil {
		t.Fatalf("decode metadata failed: %v", err)
	}

	dist := meta.Versions["4.17.21"].Dist
	if dist.Integrity != declaredIntegrity {
		t.Fatalf("metadata dist.integrity %q != declared %q", dist.Integrity, declaredIntegrity)
	}
	if dist.Shasum != declaredShasum {
		t.Fatalf("metadata dist.shasum %q != declared %q", dist.Shasum, declaredShasum)
	}

	// 2. Fetch tarball routes: unscoped and scoped (both %2F and / spellings)
	tarballRoutes := []string{
		"/lodash/-/lodash-4.17.21.tgz",
		"/@scope/pkg/-/pkg-1.2.3.tgz",
		"/@scope%2Fpkg/-/pkg-1.2.3.tgz",
	}

	for _, route := range tarballRoutes {
		t.Run("tarball_"+route, func(t *testing.T) {
			resp, err := http.Get(gwServer.URL + route)
			if err != nil {
				t.Fatalf("GET %s failed: %v", route, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status %d, want 200", resp.StatusCode)
			}

			deliveredBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read tarball body failed: %v", err)
			}

			if !bytes.Equal(deliveredBytes, tarballBytes) {
				t.Fatalf("delivered tarball bytes not byte-identical to upstream")
			}

			// Verify declared integrity against delivered bytes
			deliveredH512 := sha512.Sum512(deliveredBytes)
			computedIntegrity := "sha512-" + base64.StdEncoding.EncodeToString(deliveredH512[:])
			if computedIntegrity != dist.Integrity {
				t.Errorf("computed integrity %q does not match declared %q", computedIntegrity, dist.Integrity)
			}

			deliveredH1 := sha1.Sum(deliveredBytes)
			computedShasum := hex.EncodeToString(deliveredH1[:])
			if computedShasum != dist.Shasum {
				t.Errorf("computed shasum %q does not match declared %q", computedShasum, dist.Shasum)
			}
		})
	}
}

func TestTarballRedirectPreserved(t *testing.T) {
	redirectLocation := "https://cdn.example.com/tarballs/pkg-1.0.0.tgz"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", redirectLocation)
		w.WriteHeader(http.StatusFound)
	}))
	defer upstream.Close()

	handler, err := NewHandler(Config{
		UpstreamBaseURL: upstream.URL,
		Transport:       upstream.Client().Transport,
	})
	if err != nil {
		t.Fatalf("NewHandler() failed: %v", err)
	}
	gwServer := httptest.NewServer(handler)
	defer gwServer.Close()

	// Use client that does NOT follow redirects
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(gwServer.URL + "/lodash/-/lodash-1.0.0.tgz")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("got status %d, want 302 Found", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != redirectLocation {
		t.Errorf("got Location %q, want %q", got, redirectLocation)
	}
}

func TestHeadRequestsMatchGetHeaders(t *testing.T) {
	metaBody := []byte(`{"name":"lodash","version":"4.17.21"}`)
	tarballBody := []byte("compressed tarball data")

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".tgz") {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(tarballBody)))
			w.Header().Set("ETag", `"tarball-etag-1"`)
			w.Header().Set("Last-Modified", "Sun, 01 Jan 2025 00:00:00 GMT")
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			w.WriteHeader(http.StatusOK)
			if r.Method == http.MethodGet {
				_, _ = w.Write(tarballBody)
			}
			return
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(metaBody)))
		w.Header().Set("ETag", `"meta-etag-2"`)
		w.Header().Set("Last-Modified", "Sun, 01 Jan 2025 00:00:00 GMT")
		w.Header().Set("Cache-Control", "max-age=300")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write(metaBody)
		}
	}))
	defer upstream.Close()

	handler, err := NewHandler(Config{
		UpstreamBaseURL: upstream.URL,
		Transport:       upstream.Client().Transport,
	})
	if err != nil {
		t.Fatalf("NewHandler() failed: %v", err)
	}
	gwServer := httptest.NewServer(handler)
	defer gwServer.Close()

	routes := []string{
		"/lodash",
		"/@scope%2Fpkg",
		"/@scope/pkg",
		"/lodash/-/lodash-4.17.21.tgz",
		"/@scope/pkg/-/pkg-1.2.3.tgz",
	}

	for _, route := range routes {
		t.Run("route_"+route, func(t *testing.T) {
			getResp, err := http.Get(gwServer.URL + route)
			if err != nil {
				t.Fatalf("GET %s failed: %v", route, err)
			}
			defer getResp.Body.Close()
			_, _ = io.Copy(io.Discard, getResp.Body)

			headResp, err := http.Head(gwServer.URL + route)
			if err != nil {
				t.Fatalf("HEAD %s failed: %v", route, err)
			}
			defer headResp.Body.Close()

			if headResp.StatusCode != getResp.StatusCode {
				t.Errorf("HEAD status %d != GET status %d", headResp.StatusCode, getResp.StatusCode)
			}

			// Verify HEAD body is strictly empty
			headBody, err := io.ReadAll(headResp.Body)
			if err != nil {
				t.Fatalf("read HEAD body failed: %v", err)
			}
			if len(headBody) != 0 {
				t.Errorf("HEAD response has non-empty body: %d bytes", len(headBody))
			}

			// Verify headers package managers rely on match between GET and HEAD
			criticalHeaders := []string{
				"Content-Type",
				"Content-Length",
				"ETag",
				"Last-Modified",
				"Cache-Control",
			}
			for _, h := range criticalHeaders {
				getVal := getResp.Header.Get(h)
				headVal := headResp.Header.Get(h)
				if getVal != headVal {
					t.Errorf("header %s mismatch: GET=%q, HEAD=%q", h, getVal, headVal)
				}
			}
		})
	}
}

func TestNonexistentPackagePassesThrough404(t *testing.T) {
	notFoundJSON := []byte(`{"error":"Not found"}`)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write(notFoundJSON)
	}))
	defer upstream.Close()

	handler, err := NewHandler(Config{
		UpstreamBaseURL: upstream.URL,
		Transport:       upstream.Client().Transport,
	})
	if err != nil {
		t.Fatalf("NewHandler() failed: %v", err)
	}
	gwServer := httptest.NewServer(handler)
	defer gwServer.Close()

	resp, err := http.Get(gwServer.URL + "/nonexistent-pkg-abc-123")
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("got status %d, want 404", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body failed: %v", err)
	}
	if !bytes.Equal(body, notFoundJSON) {
		t.Errorf("got %s, want %s", body, notFoundJSON)
	}

	assertNonAccusatory(t, string(body))
}

func TestUnsupportedMethodsAndRoutesFailNonAccusatory(t *testing.T) {
	handler, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("NewHandler() failed: %v", err)
	}
	gwServer := httptest.NewServer(handler)
	defer gwServer.Close()

	// 1. Unsupported HTTP methods (mutation, publication)
	unsupportedMethods := []string{
		http.MethodPut,
		http.MethodPost,
		http.MethodDelete,
		http.MethodPatch,
	}

	for _, method := range unsupportedMethods {
		t.Run("method_"+method, func(t *testing.T) {
			req, _ := http.NewRequest(method, gwServer.URL+"/lodash", strings.NewReader("payload"))
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusMethodNotAllowed {
				t.Errorf("got status %d, want 405 Method Not Allowed", resp.StatusCode)
			}
			if allow := resp.Header.Get("Allow"); !strings.Contains(allow, "GET") {
				t.Errorf("Allow header missing GET: %q", allow)
			}

			body, _ := io.ReadAll(resp.Body)
			assertNonAccusatory(t, string(body))
		})
	}

	// 2. Unsupported /-/ service routes and invalid paths
	unsupportedRoutes := []string{
		"/-/whoami",
		"/-/all",
		"/-/npm/v1/user",
		"/-/user/token",
		"/-/ping",
		"/",
		"/lodash/extra/extra/nested",
	}

	for _, route := range unsupportedRoutes {
		t.Run("route_"+route, func(t *testing.T) {
			resp, err := http.Get(gwServer.URL + route)
			if err != nil {
				t.Fatalf("GET %s failed: %v", route, err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("GET %s: got status %d, want 400 Bad Request", route, resp.StatusCode)
			}

			body, _ := io.ReadAll(resp.Body)
			assertNonAccusatory(t, string(body))
		})
	}

	// 3. Private-registry flow: request with Authorization header
	t.Run("private_registry_auth", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, gwServer.URL+"/lodash", nil)
		secretToken := "secret-token-abcdef123456"
		req.Header.Set("Authorization", "Bearer "+secretToken)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("got status %d, want 400 Bad Request", resp.StatusCode)
		}

		body, _ := io.ReadAll(resp.Body)
		text := string(body)
		assertNonAccusatory(t, text)

		if strings.Contains(text, secretToken) {
			t.Fatalf("response leaked secret token: %s", text)
		}
		if strings.Contains(text, "Bearer") {
			t.Fatalf("response leaked auth scheme: %s", text)
		}
	})
}

func TestRequestTimeout(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(500 * time.Millisecond):
			w.WriteHeader(http.StatusOK)
		case <-r.Context().Done():
			// Client cancelled / timed out
			return
		}
	}))
	defer upstream.Close()

	handler, err := NewHandler(Config{
		UpstreamBaseURL: upstream.URL,
		Transport:       upstream.Client().Transport,
		Timeout:         50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewHandler() failed: %v", err)
	}
	gwServer := httptest.NewServer(handler)
	defer gwServer.Close()

	resp, err := http.Get(gwServer.URL + "/lodash")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("got status %d, want 504 Gateway Timeout", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "gateway timeout") {
		t.Errorf("unexpected body: %s", string(body))
	}
	assertNonAccusatory(t, string(body))
}

func TestResponseBodyLimit(t *testing.T) {
	t.Run("content_length_exceeded", func(t *testing.T) {
		largePayload := make([]byte, 2048)

		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(largePayload)))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(largePayload)
		}))
		defer upstream.Close()

		handler, err := NewHandler(Config{
			UpstreamBaseURL: upstream.URL,
			Transport:       upstream.Client().Transport,
			MaxBodyBytes:    1024,
		})
		if err != nil {
			t.Fatalf("NewHandler() failed: %v", err)
		}
		gwServer := httptest.NewServer(handler)
		defer gwServer.Close()

		resp, err := http.Get(gwServer.URL + "/lodash/-/lodash-1.0.0.tgz")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("got status %d, want 502 Bad Gateway", resp.StatusCode)
		}

		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "response body exceeds size limit") {
			t.Errorf("unexpected error text: %s", string(body))
		}
		assertNonAccusatory(t, string(body))
	})

	t.Run("chunked_stream_exceeded", func(t *testing.T) {
		largePayload := make([]byte, 2048)

		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Chunked: omit Content-Length
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			_, _ = w.Write(largePayload)
		}))
		defer upstream.Close()

		handler, err := NewHandler(Config{
			UpstreamBaseURL: upstream.URL,
			Transport:       upstream.Client().Transport,
			MaxBodyBytes:    1024,
		})
		if err != nil {
			t.Fatalf("NewHandler() failed: %v", err)
		}
		gwServer := httptest.NewServer(handler)
		defer gwServer.Close()

		resp, err := http.Get(gwServer.URL + "/lodash/-/lodash-1.0.0.tgz")
		if err == nil {
			defer resp.Body.Close()
			readBytes, _ := io.ReadAll(resp.Body)
			if len(readBytes) > 1024 {
				t.Fatalf("client received %d bytes, should not exceed limit 1024", len(readBytes))
			}
		}
		// If transfer aborted, error or truncated read is the expected outcome
	})
}

func TestContextCancellationReleasesUpstream(t *testing.T) {
	upstreamCancelled := make(chan struct{})

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}

		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-r.Context().Done():
				close(upstreamCancelled)
				return
			case <-ticker.C:
				if _, err := w.Write([]byte("data-chunk\n")); err != nil {
					close(upstreamCancelled)
					return
				}
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
			}
		}
	}))
	defer upstream.Close()

	handler, err := NewHandler(Config{
		UpstreamBaseURL: upstream.URL,
		Transport:       upstream.Client().Transport,
	})
	if err != nil {
		t.Fatalf("NewHandler() failed: %v", err)
	}
	gwServer := httptest.NewServer(handler)
	defer gwServer.Close()

	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, gwServer.URL+"/lodash/-/lodash-1.0.0.tgz", nil)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("client request failed: %v", err)
	}

	// Read first byte to ensure stream is established
	var b [1]byte
	_, _ = resp.Body.Read(b[:])

	// Cancel client context
	cancel()
	_ = resp.Body.Close()

	select {
	case <-upstreamCancelled:
		// Upstream connection was successfully released by cancellation
	case <-time.After(2 * time.Second):
		t.Fatal("upstream connection was not released after context cancellation")
	}
}

func TestSanitizedErrors(t *testing.T) {
	secretBody := "DATABASE_SECRET_KEY=supersecret98765 PRIVATE TRACE"

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(secretBody))
	}))
	defer upstream.Close()

	handler, err := NewHandler(Config{
		UpstreamBaseURL: upstream.URL,
		Transport:       upstream.Client().Transport,
	})
	if err != nil {
		t.Fatalf("NewHandler() failed: %v", err)
	}
	gwServer := httptest.NewServer(handler)
	defer gwServer.Close()

	resp, err := http.Get(gwServer.URL + "/lodash")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("got status %d, want 502 Bad Gateway", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if strings.Contains(bodyStr, "supersecret") || strings.Contains(bodyStr, "DATABASE_SECRET_KEY") || strings.Contains(bodyStr, "PRIVATE TRACE") {
		t.Fatalf("gateway response leaked upstream error body fragment: %s", bodyStr)
	}

	assertNonAccusatory(t, bodyStr)

	// Test connection failure (upstream down)
	downHandler, err := NewHandler(Config{
		UpstreamBaseURL: "http://127.0.0.1:1", // guaranteed invalid port
	})
	if err != nil {
		t.Fatalf("NewHandler() failed: %v", err)
	}
	downServer := httptest.NewServer(downHandler)
	defer downServer.Close()

	downResp, err := http.Get(downServer.URL + "/lodash")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer downResp.Body.Close()

	if downResp.StatusCode != http.StatusBadGateway {
		t.Fatalf("got status %d, want 502", downResp.StatusCode)
	}

	downBody, _ := io.ReadAll(downResp.Body)
	downStr := string(downBody)
	if strings.Contains(downStr, "127.0.0.1:1") {
		t.Fatalf("gateway response leaked internal address: %s", downStr)
	}
	assertNonAccusatory(t, downStr)
}

func TestHealthRoute(t *testing.T) {
	handler, err := NewHandler(Config{})
	if err != nil {
		t.Fatalf("NewHandler() failed: %v", err)
	}
	gwServer := httptest.NewServer(handler)
	defer gwServer.Close()

	// GET
	resp, err := http.Get(gwServer.URL + "/-/installgate/health")
	if err != nil {
		t.Fatalf("GET /-/installgate/health failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got status %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"status":"ok"`) {
		t.Errorf("unexpected body: %s", string(body))
	}

	// HEAD
	headResp, err := http.Head(gwServer.URL + "/-/installgate/health")
	if err != nil {
		t.Fatalf("HEAD /-/installgate/health failed: %v", err)
	}
	defer headResp.Body.Close()

	if headResp.StatusCode != http.StatusOK {
		t.Fatalf("got status %d, want 200", headResp.StatusCode)
	}
	headBody, _ := io.ReadAll(headResp.Body)
	if len(headBody) != 0 {
		t.Errorf("expected empty body for HEAD, got %d bytes", len(headBody))
	}
}

func TestHealthAndReadinessWithCacheFreshness(t *testing.T) {
	cache := evidence.NewMemoryCache()
	now := time.Now().UTC()
	freshOutcome := evidence.NewAvailableOutcome(evidence.KindVulnerability, "osv", nil, now, now.Add(1*time.Hour))
	cache.Put("test-pkg", "1.0.0", freshOutcome, now.Add(5*time.Hour))

	handler, err := NewHandler(Config{
		Cache: cache,
	})
	if err != nil {
		t.Fatalf("NewHandler() failed: %v", err)
	}
	gwServer := httptest.NewServer(handler)
	defer gwServer.Close()

	// 1. Check readiness route
	readyResp, err := http.Get(gwServer.URL + "/-/installgate/ready")
	if err != nil {
		t.Fatalf("GET /-/installgate/ready failed: %v", err)
	}
	defer readyResp.Body.Close()
	if readyResp.StatusCode != http.StatusOK {
		t.Fatalf("got ready status %d, want 200", readyResp.StatusCode)
	}
	var readyBody map[string]any
	if err := json.NewDecoder(readyResp.Body).Decode(&readyBody); err != nil {
		t.Fatalf("failed to parse ready JSON: %v", err)
	}
	if readyBody["status"] != "ok" || readyBody["ready"] != true {
		t.Errorf("unexpected ready body: %+v", readyBody)
	}

	// 2. Check health route with cache freshness
	healthResp, err := http.Get(gwServer.URL + "/-/installgate/health")
	if err != nil {
		t.Fatalf("GET /-/installgate/health failed: %v", err)
	}
	defer healthResp.Body.Close()
	if healthResp.StatusCode != http.StatusOK {
		t.Fatalf("got health status %d, want 200", healthResp.StatusCode)
	}
	var healthBody struct {
		Status string              `json:"status"`
		Ready  bool                `json:"ready"`
		Cache  evidence.CacheStats `json:"cache"`
	}
	if err := json.NewDecoder(healthResp.Body).Decode(&healthBody); err != nil {
		t.Fatalf("failed to parse health JSON: %v", err)
	}
	if healthBody.Status != "ok" || !healthBody.Ready {
		t.Errorf("unexpected health status/ready: %+v", healthBody)
	}
	if healthBody.Cache.TotalEntries != 1 || healthBody.Cache.FreshEntries != 1 {
		t.Errorf("unexpected cache freshness stats: %+v", healthBody.Cache)
	}
}
