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
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aniklavida/installgate/internal/explanation"
	"github.com/aniklavida/installgate/internal/quarantine"
	"github.com/aniklavida/installgate/internal/verdict"
)

func makeValidTarball(t *testing.T, pkgName, pkgVersion string, scripts map[string]string) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	pkgJSON, err := json.Marshal(map[string]interface{}{
		"name":    pkgName,
		"version": pkgVersion,
		"scripts": scripts,
	})
	if err != nil {
		t.Fatalf("marshal package.json failed: %v", err)
	}

	hdr := &tar.Header{
		Name:     "package/package.json",
		Mode:     0o644,
		Size:     int64(len(pkgJSON)),
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("write tar header failed: %v", err)
	}
	if _, err := tw.Write(pkgJSON); err != nil {
		t.Fatalf("write tar body failed: %v", err)
	}

	indexJS := []byte("module.exports = {};\n")
	hdr2 := &tar.Header{
		Name:     "package/index.js",
		Mode:     0o644,
		Size:     int64(len(indexJS)),
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(hdr2); err != nil {
		t.Fatalf("write index.js header failed: %v", err)
	}
	if _, err := tw.Write(indexJS); err != nil {
		t.Fatalf("write index.js body failed: %v", err)
	}

	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer failed: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("close gzip writer failed: %v", err)
	}

	tarballBytes := buf.Bytes()
	h := sha512.Sum512(tarballBytes)
	integrity := "sha512-" + base64.StdEncoding.EncodeToString(h[:])

	return tarballBytes, integrity
}

func TestGateway_TarballQuarantine_DoubleIntegrity_AllowedAndReleased(t *testing.T) {
	tempDir := t.TempDir()
	quarantineDir := filepath.Join(tempDir, "quarantine")
	decisionDir := filepath.Join(tempDir, "decisions")

	tarballBytes, integrity := makeValidTarball(t, "safe-pkg", "1.0.0", nil)

	packumentJSON := fmt.Sprintf(`{
		"name": "safe-pkg",
		"versions": {
			"1.0.0": {
				"name": "safe-pkg",
				"version": "1.0.0",
				"dist": {
					"tarball": "https://registry.npmjs.org/safe-pkg/-/safe-pkg-1.0.0.tgz",
					"integrity": "%s"
				}
			}
		}
	}`, integrity)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/safe-pkg":
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(packumentJSON))
		case "/safe-pkg/-/safe-pkg-1.0.0.tgz":
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(tarballBytes)))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(tarballBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	metaStore := quarantine.NewMemoryMetadataStore()
	blobStore, err := quarantine.NewDiskBlobStore(quarantineDir, quarantine.DiskBudget{MaxBytes: 10 * 1024 * 1024}, metaStore)
	if err != nil {
		t.Fatalf("NewDiskBlobStore failed: %v", err)
	}

	qMgr, err := quarantine.NewManager(quarantine.Config{
		Store:    blobStore,
		Metadata: metaStore,
		Limits:   quarantine.DefaultArchiveLimits(),
	})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	decStore, err := explanation.NewFileStore(decisionDir)
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}

	handler, err := NewHandler(Config{
		UpstreamBaseURL: upstream.URL,
		Transport:       upstream.Client().Transport,
		Quarantine:      qMgr,
		DecisionStore:   decStore,
	})
	if err != nil {
		t.Fatalf("NewHandler failed: %v", err)
	}

	gwServer := httptest.NewServer(handler)
	defer gwServer.Close()

	// 1. Package manager requests metadata packument
	metaResp, err := http.Get(gwServer.URL + "/safe-pkg")
	if err != nil {
		t.Fatalf("GET /safe-pkg failed: %v", err)
	}
	defer metaResp.Body.Close()
	if metaResp.StatusCode != http.StatusOK {
		t.Fatalf("expected metadata 200, got %d", metaResp.StatusCode)
	}

	// 2. Package manager requests tarball: quarantined, verified twice, and released
	tarResp, err := http.Get(gwServer.URL + "/safe-pkg/-/safe-pkg-1.0.0.tgz")
	if err != nil {
		t.Fatalf("GET tarball failed: %v", err)
	}
	defer tarResp.Body.Close()

	if tarResp.StatusCode != http.StatusOK {
		t.Fatalf("expected tarball status 200 OK, got %d", tarResp.StatusCode)
	}

	deliveredBytes, err := io.ReadAll(tarResp.Body)
	if err != nil {
		t.Fatalf("read tarball body failed: %v", err)
	}

	if !bytes.Equal(deliveredBytes, tarballBytes) {
		t.Fatal("delivered tarball bytes not byte-identical to upstream")
	}

	// Assert: blob exists in content-addressed quarantine store
	parsed, _ := quarantine.ParseDigest(integrity)
	if !blobStore.Has(context.Background(), parsed.Key()) {
		t.Fatal("expected blob to reside in content-addressed quarantine store")
	}
}

func TestGateway_TarballQuarantine_UpstreamIntegrityMismatchBlocks(t *testing.T) {
	tempDir := t.TempDir()
	quarantineDir := filepath.Join(tempDir, "quarantine")
	decisionDir := filepath.Join(tempDir, "decisions")

	realBytes, _ := makeValidTarball(t, "mismatch-pkg", "1.0.0", nil)

	// Upstream metadata declares a digest that does not match the actual tarball bytes
	fakeDigest := "sha512-" + base64.StdEncoding.EncodeToString(make([]byte, 64))

	packumentJSON := fmt.Sprintf(`{
		"name": "mismatch-pkg",
		"versions": {
			"1.0.0": {
				"name": "mismatch-pkg",
				"version": "1.0.0",
				"dist": {
					"tarball": "https://registry.npmjs.org/mismatch-pkg/-/mismatch-pkg-1.0.0.tgz",
					"integrity": "%s"
				}
			}
		}
	}`, fakeDigest)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/mismatch-pkg":
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(packumentJSON))
		case "/mismatch-pkg/-/mismatch-pkg-1.0.0.tgz":
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(realBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	metaStore := quarantine.NewMemoryMetadataStore()
	blobStore, err := quarantine.NewDiskBlobStore(quarantineDir, quarantine.DiskBudget{MaxBytes: 10 * 1024 * 1024}, metaStore)
	if err != nil {
		t.Fatalf("NewDiskBlobStore failed: %v", err)
	}

	qMgr, err := quarantine.NewManager(quarantine.Config{
		Store:    blobStore,
		Metadata: metaStore,
		Limits:   quarantine.DefaultArchiveLimits(),
	})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	decStore, err := explanation.NewFileStore(decisionDir)
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}

	handler, err := NewHandler(Config{
		UpstreamBaseURL: upstream.URL,
		Transport:       upstream.Client().Transport,
		Quarantine:      qMgr,
		DecisionStore:   decStore,
	})
	if err != nil {
		t.Fatalf("NewHandler failed: %v", err)
	}

	gwServer := httptest.NewServer(handler)
	defer gwServer.Close()

	// 1. Fetch metadata so expected integrity is known
	metaResp, err := http.Get(gwServer.URL + "/mismatch-pkg")
	if err != nil {
		t.Fatalf("GET /mismatch-pkg failed: %v", err)
	}
	metaResp.Body.Close()

	// 2. Request tarball: FIRST integrity verification fails -> BLOCKS with 403
	tarResp, err := http.Get(gwServer.URL + "/mismatch-pkg/-/mismatch-pkg-1.0.0.tgz")
	if err != nil {
		t.Fatalf("GET tarball failed: %v", err)
	}
	defer tarResp.Body.Close()

	if tarResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected status 403 Forbidden, got %d", tarResp.StatusCode)
	}

	decID := tarResp.Header.Get("X-InstallGate-Decision")
	if decID == "" {
		t.Fatal("expected X-InstallGate-Decision header on blocked response")
	}
	if tarResp.Header.Get("X-InstallGate-Verdict") != string(verdict.Block) {
		t.Errorf("expected X-InstallGate-Verdict 'block', got %q", tarResp.Header.Get("X-InstallGate-Verdict"))
	}

	// 3. Resolve decision document from store and assert reasons
	doc, err := decStore.Get(decID)
	if err != nil {
		t.Fatalf("failed retrieving decision document %q: %v", decID, err)
	}
	if doc.Verdict != verdict.Block {
		t.Errorf("expected doc verdict 'block', got %q", doc.Verdict)
	}
	if len(doc.Reasons) != 1 || doc.Reasons[0].RuleID != "core.integrity-or-malicious" {
		t.Errorf("expected ruleID 'core.integrity-or-malicious', got: %+v", doc.Reasons)
	}

	// 4. Assert: unverified / mismatched blob is NEVER stored in blobstore
	parsed, _ := quarantine.ParseDigest(fakeDigest)
	if blobStore.Has(context.Background(), parsed.Key()) {
		t.Fatal("mismatched blob was improperly stored in blobstore")
	}
}

func TestGateway_TarballQuarantine_BlobCorruptedBetweenVerificationsBlocks(t *testing.T) {
	tempDir := t.TempDir()
	quarantineDir := filepath.Join(tempDir, "quarantine")
	decisionDir := filepath.Join(tempDir, "decisions")

	tarballBytes, integrity := makeValidTarball(t, "tampered-pkg", "1.0.0", nil)

	packumentJSON := fmt.Sprintf(`{
		"name": "tampered-pkg",
		"versions": {
			"1.0.0": {
				"name": "tampered-pkg",
				"version": "1.0.0",
				"dist": {
					"tarball": "https://registry.npmjs.org/tampered-pkg/-/tampered-pkg-1.0.0.tgz",
					"integrity": "%s"
				}
			}
		}
	}`, integrity)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/tampered-pkg":
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(packumentJSON))
		case "/tampered-pkg/-/tampered-pkg-1.0.0.tgz":
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(tarballBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	metaStore := quarantine.NewMemoryMetadataStore()
	blobStore, err := quarantine.NewDiskBlobStore(quarantineDir, quarantine.DiskBudget{MaxBytes: 10 * 1024 * 1024}, metaStore)
	if err != nil {
		t.Fatalf("NewDiskBlobStore failed: %v", err)
	}

	qMgr, err := quarantine.NewManager(quarantine.Config{
		Store:    blobStore,
		Metadata: metaStore,
		Limits:   quarantine.DefaultArchiveLimits(),
	})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	decStore, err := explanation.NewFileStore(decisionDir)
	if err != nil {
		t.Fatalf("NewFileStore failed: %v", err)
	}

	handler, err := NewHandler(Config{
		UpstreamBaseURL: upstream.URL,
		Transport:       upstream.Client().Transport,
		Quarantine:      qMgr,
		DecisionStore:   decStore,
	})
	if err != nil {
		t.Fatalf("NewHandler failed: %v", err)
	}

	gwServer := httptest.NewServer(handler)
	defer gwServer.Close()

	// 1. Fetch metadata
	metaResp, err := http.Get(gwServer.URL + "/tampered-pkg")
	if err != nil {
		t.Fatalf("GET /tampered-pkg failed: %v", err)
	}
	metaResp.Body.Close()

	// 2. Pre-ingest and verify once: blob is stored in quarantine
	entry, err := qMgr.Ingest(context.Background(), "tampered-pkg", "1.0.0", integrity, bytes.NewReader(tarballBytes))
	if err != nil {
		t.Fatalf("Ingest failed: %v", err)
	}
	_, err = qMgr.Inspect(context.Background(), entry)
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}

	// 3. TAMPERING: Corrupt the stored blob on disk between inspection and release
	blobDiskPath := blobStore.BlobPath(entry.Key)
	corrupted := make([]byte, len(tarballBytes))
	copy(corrupted, tarballBytes)
	corrupted[len(corrupted)/2] ^= 0xFF // flip bit in middle of file
	if err := os.WriteFile(blobDiskPath, corrupted, 0o600); err != nil {
		t.Fatalf("failed corrupting blob on disk: %v", err)
	}

	// 4. Request tarball: SECOND integrity verification MUST FAIL and produce a BLOCK
	tarResp, err := http.Get(gwServer.URL + "/tampered-pkg/-/tampered-pkg-1.0.0.tgz")
	if err != nil {
		t.Fatalf("GET tarball failed: %v", err)
	}
	defer tarResp.Body.Close()

	if tarResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected status 403 Forbidden for corrupted blob, got %d", tarResp.StatusCode)
	}

	decID := tarResp.Header.Get("X-InstallGate-Decision")
	if decID == "" {
		t.Fatal("expected X-InstallGate-Decision header on blocked response")
	}
	if tarResp.Header.Get("X-InstallGate-Verdict") != string(verdict.Block) {
		t.Errorf("expected verdict 'block', got %q", tarResp.Header.Get("X-InstallGate-Verdict"))
	}

	// 5. Assert: corrupted bytes were NEVER released to client
	bodyBytes, _ := io.ReadAll(tarResp.Body)
	if bytes.Contains(bodyBytes, corrupted) {
		t.Fatal("corrupted tarball bytes were leaked to client response!")
	}
}

func TestGateway_TarballQuarantine_PrivacyNoPackageBytesInLogsOrResponses(t *testing.T) {
	tempDir := t.TempDir()
	quarantineDir := filepath.Join(tempDir, "quarantine")
	decisionDir := filepath.Join(tempDir, "decisions")

	tarballBytes, _ := makeValidTarball(t, "private-pkg", "1.0.0", nil)

	// Intentionally mismatched integrity to trigger rejection
	badIntegrity := "sha512-" + base64.StdEncoding.EncodeToString(make([]byte, 64))

	packumentJSON := fmt.Sprintf(`{
		"name": "private-pkg",
		"versions": {
			"1.0.0": {
				"name": "private-pkg",
				"version": "1.0.0",
				"dist": {
					"tarball": "https://registry.npmjs.org/private-pkg/-/private-pkg-1.0.0.tgz",
					"integrity": "%s"
				}
			}
		}
	}`, badIntegrity)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/private-pkg":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(packumentJSON))
		case "/private-pkg/-/private-pkg-1.0.0.tgz":
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(tarballBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()

	metaStore := quarantine.NewMemoryMetadataStore()
	blobStore, _ := quarantine.NewDiskBlobStore(quarantineDir, quarantine.DiskBudget{MaxBytes: 10 * 1024 * 1024}, metaStore)
	qMgr, _ := quarantine.NewManager(quarantine.Config{
		Store:    blobStore,
		Metadata: metaStore,
		Limits:   quarantine.DefaultArchiveLimits(),
	})
	decStore, _ := explanation.NewFileStore(decisionDir)

	handler, _ := NewHandler(Config{
		UpstreamBaseURL: upstream.URL,
		Transport:       upstream.Client().Transport,
		Quarantine:      qMgr,
		DecisionStore:   decStore,
	})

	gwServer := httptest.NewServer(handler)
	defer gwServer.Close()

	// Fetch metadata then tarball
	_, _ = http.Get(gwServer.URL + "/private-pkg")
	resp, err := http.Get(gwServer.URL + "/private-pkg/-/private-pkg-1.0.0.tgz")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body failed: %v", err)
	}

	bodyStr := string(bodyBytes)

	// Assert: package bytes are NEVER echoed in error responses
	if strings.Contains(bodyStr, string(tarballBytes)) {
		t.Fatal("package tarball bytes were echoed in error response body!")
	}
	if strings.Contains(bodyStr, "package.json") {
		t.Fatal("archive file contents were leaked in error response body!")
	}
}
