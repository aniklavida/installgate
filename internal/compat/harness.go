package compat

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/aniklavida/installgate/internal/evidence"
	"github.com/aniklavida/installgate/internal/gateway"
	"github.com/aniklavida/installgate/internal/policy"
	"github.com/aniklavida/installgate/internal/quarantine"
	"github.com/aniklavida/installgate/internal/store"
)

var (
	// ErrClientNotInstalled is returned when a client binary is absent on the host.
	ErrClientNotInstalled = errors.New("package manager binary not installed on host")
)

// CapturedHeader records client request headers arriving at upstream.
type CapturedHeader struct {
	Method          string
	Path            string
	Accept          string
	IfNoneMatch     string
	IfModifiedSince string
	UserAgent       string
}

// TestHarness wires an upstream fixture registry, an isolated InstallGate gateway with full quarantine,
// and execution environments for npm, pnpm, Yarn and Bun.
type TestHarness struct {
	DataDir        string
	UpstreamServer *httptest.Server
	GatewayServer  *httptest.Server
	GatewayHandler *gateway.Handler
	QuarantineMgr  *quarantine.Manager
	BlobStore      *quarantine.DiskBlobStore
	DBStore        store.Store
	Packages       map[string]*FixturePackage

	mu              sync.Mutex
	capturedHeaders []CapturedHeader
	corruptedMap    map[string]bool
	requestCount    map[string]int
}

// NewTestHarness constructs an isolated in-process integration harness.
func NewTestHarness(t *testing.T) *TestHarness {
	t.Helper()

	dataDir := t.TempDir()
	pkgs, err := DefaultFixtureRegistry()
	if err != nil {
		t.Fatalf("failed creating default fixture registry: %v", err)
	}

	h := &TestHarness{
		DataDir:         dataDir,
		Packages:        pkgs,
		corruptedMap:    make(map[string]bool),
		requestCount:    make(map[string]int),
		capturedHeaders: make([]CapturedHeader, 0),
	}

	// 1. Start Upstream Server
	h.UpstreamServer = httptest.NewServer(http.HandlerFunc(h.handleUpstreamRequest))

	// 2. Initialize Database and Migrations
	dbPath := filepath.Join(dataDir, "installgate.db")
	dbStore, err := store.OpenSQLite(dbPath)
	if err != nil {
		t.Fatalf("failed initializing SQLite: %v", err)
	}
	if err := dbStore.ApplyMigrations(context.Background()); err != nil {
		t.Fatalf("failed applying DB migrations: %v", err)
	}
	h.DBStore = dbStore

	// 3. Initialize Quarantine
	quarantineDir := filepath.Join(dataDir, "quarantine")
	metaStore := quarantine.NewMemoryMetadataStore()
	blobStore, err := quarantine.NewDiskBlobStore(quarantineDir, quarantine.DiskBudget{MaxBytes: 50 * 1024 * 1024}, metaStore)
	if err != nil {
		t.Fatalf("failed initializing blob store: %v", err)
	}
	h.BlobStore = blobStore
	qMgr, err := quarantine.NewManager(quarantine.Config{
		Store:    blobStore,
		Metadata: metaStore,
		Limits:   quarantine.DefaultArchiveLimits(),
	})
	if err != nil {
		t.Fatalf("failed initializing quarantine manager: %v", err)
	}
	h.QuarantineMgr = qMgr

	// 4. Initialize Policy & Evaluator
	cache := evidence.NewMemoryCache()
	pol := policy.NewDefaultPolicy()
	assembler := evidence.NewAssembler(
		evidence.WithCache(cache),
		evidence.WithFreshnessPolicy(evidence.DefaultFreshnessPolicy()),
	)
	engine := gateway.NewEngine(gateway.EngineConfig{
		Policy:    pol,
		Assembler: assembler,
		Store:     dbStore,
		Actor:     "compat-harness",
	})

	// 5. Initialize Gateway Handler
	gwHandler, err := gateway.NewHandler(gateway.Config{
		UpstreamBaseURL: h.UpstreamServer.URL,
		Evaluator:       engine,
		DecisionStore:   dbStore,
		Quarantine:      h.QuarantineMgr,
		Cache:           cache,
	})
	if err != nil {
		t.Fatalf("failed initializing gateway handler: %v", err)
	}
	h.GatewayHandler = gwHandler

	// 6. Start Gateway Server
	h.GatewayServer = httptest.NewServer(gwHandler)

	t.Cleanup(func() {
		h.Close()
	})

	return h
}

// Close shuts down test servers and storage cleanly.
func (h *TestHarness) Close() {
	if h.GatewayServer != nil {
		h.GatewayServer.Close()
	}
	if h.UpstreamServer != nil {
		h.UpstreamServer.Close()
	}
	if h.DBStore != nil {
		_ = h.DBStore.Close()
	}
}

// GatewayURL returns the listening base URL of the InstallGate gateway.
func (h *TestHarness) GatewayURL() string {
	return h.GatewayServer.URL
}

// UpstreamURL returns the listening base URL of the upstream fixture registry.
func (h *TestHarness) UpstreamURL() string {
	return h.UpstreamServer.URL
}

// SetCorrupted sets whether upstream delivers corrupted tarball bytes for the named package.
func (h *TestHarness) SetCorrupted(pkgName string, corrupted bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.corruptedMap[pkgName] = corrupted
}

// CapturedHeaders returns a copy of all headers captured by the upstream fixture registry.
func (h *TestHarness) CapturedHeaders() []CapturedHeader {
	h.mu.Lock()
	defer h.mu.Unlock()
	copied := make([]CapturedHeader, len(h.capturedHeaders))
	copy(copied, h.capturedHeaders)
	return copied
}

func (h *TestHarness) handleUpstreamRequest(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.capturedHeaders = append(h.capturedHeaders, CapturedHeader{
		Method:          r.Method,
		Path:            r.URL.EscapedPath(),
		Accept:          r.Header.Get("Accept"),
		IfNoneMatch:     r.Header.Get("If-None-Match"),
		IfModifiedSince: r.Header.Get("If-Modified-Since"),
		UserAgent:       r.Header.Get("User-Agent"),
	})
	h.requestCount[r.URL.Path]++
	h.mu.Unlock()

	escapedPath := r.URL.EscapedPath()
	decodedPath, err := url.PathUnescape(escapedPath)
	if err != nil {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	cleanPath := strings.TrimPrefix(decodedPath, "/")

	// Tarball request: e.g. "fixture-unscoped/-/fixture-unscoped-1.0.0.tgz"
	// or "@testscope/fixture-scoped/-/fixture-scoped-1.0.0.tgz"
	if strings.HasSuffix(cleanPath, ".tgz") {
		h.serveTarball(w, r, cleanPath)
		return
	}

	// Metadata packument request: e.g. "fixture-unscoped" or "@testscope/fixture-scoped"
	h.servePackument(w, r, cleanPath)
}

func (h *TestHarness) servePackument(w http.ResponseWriter, r *http.Request, pkgName string) {
	pkg, exists := h.Packages[pkgName]
	if !exists {
		http.NotFound(w, r)
		return
	}

	etag := fmt.Sprintf(`W/"etag-%s-%s"`, pkg.Name, pkg.Version)
	lastModified := "Wed, 17 Sep 2025 00:00:00 GMT"

	// Conditional Request handling: byte-fidelity check for 304 Not Modified
	if r.Header.Get("If-None-Match") == etag {
		w.Header().Set("ETag", etag)
		w.Header().Set("Last-Modified", lastModified)
		w.WriteHeader(http.StatusNotModified)
		return
	}

	tarballFilename := fmt.Sprintf("%s-%s.tgz", tarballBaseName(pkg.Name), pkg.Version)
	tarballURL := fmt.Sprintf("%s/%s/-/%s", h.GatewayURL(), pkg.Name, tarballFilename)

	accept := r.Header.Get("Accept")
	isAbbreviated := strings.Contains(accept, "application/vnd.npm.install-v1+json")

	w.Header().Set("ETag", etag)
	w.Header().Set("Last-Modified", lastModified)

	if isAbbreviated {
		w.Header().Set("Content-Type", "application/vnd.npm.install-v1+json; charset=utf-8")
		body := map[string]any{
			"name":     pkg.Name,
			"modified": "2025-09-17T00:00:00.000Z",
			"dist-tags": map[string]string{
				"latest": pkg.Version,
			},
			"versions": map[string]any{
				pkg.Version: map[string]any{
					"name":    pkg.Name,
					"version": pkg.Version,
					"dist": map[string]string{
						"tarball":   tarballURL,
						"shasum":    pkg.ShasumSHA1,
						"integrity": pkg.IntegritySHA512,
					},
					"dependencies":         pkg.Dependencies,
					"peerDependencies":     pkg.PeerDependencies,
					"optionalDependencies": pkg.OptionalDependencies,
				},
			},
		}
		data, _ := json.Marshal(body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	body := map[string]any{
		"_id":         pkg.Name,
		"name":        pkg.Name,
		"description": pkg.Description,
		"dist-tags": map[string]string{
			"latest": pkg.Version,
		},
		"versions": map[string]any{
			pkg.Version: map[string]any{
				"name":        pkg.Name,
				"version":     pkg.Version,
				"description": pkg.Description,
				"dist": map[string]string{
					"tarball":   tarballURL,
					"shasum":    pkg.ShasumSHA1,
					"integrity": pkg.IntegritySHA512,
				},
				"dependencies":         pkg.Dependencies,
				"peerDependencies":     pkg.PeerDependencies,
				"optionalDependencies": pkg.OptionalDependencies,
			},
		},
	}
	data, _ := json.Marshal(body)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (h *TestHarness) serveTarball(w http.ResponseWriter, r *http.Request, path string) {
	// Identify package name
	var targetPkg *FixturePackage
	for _, pkg := range h.Packages {
		tarballFilename := fmt.Sprintf("%s-%s.tgz", tarballBaseName(pkg.Name), pkg.Version)
		if strings.HasSuffix(path, tarballFilename) {
			targetPkg = pkg
			break
		}
	}

	if targetPkg == nil {
		http.NotFound(w, r)
		return
	}

	h.mu.Lock()
	corrupted := h.corruptedMap[targetPkg.Name]
	h.mu.Unlock()

	tarballData := targetPkg.TarballBytes
	if corrupted {
		// Flip one bit in middle of archive to simulate network or transport corruption
		corruptedCopy := make([]byte, len(tarballData))
		copy(corruptedCopy, tarballData)
		if len(corruptedCopy) > 64 {
			corruptedCopy[64] ^= 0xFF
		} else if len(corruptedCopy) > 0 {
			corruptedCopy[len(corruptedCopy)/2] ^= 0xFF
		}
		tarballData = corruptedCopy
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(tarballData)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(tarballData)
}

func tarballBaseName(pkgName string) string {
	if idx := strings.LastIndex(pkgName, "/"); idx >= 0 {
		return pkgName[idx+1:]
	}
	return pkgName
}

// RunCmd executes a package manager or shell command in the specified directory with isolated environment variables.
func RunCmd(ctx context.Context, dir string, envExtra []string, bin string, args ...string) (string, string, int, error) {
	binPath, err := exec.LookPath(bin)
	if err != nil {
		return "", "", -1, fmt.Errorf("%w: %s", ErrClientNotInstalled, bin)
	}

	cmd := exec.CommandContext(ctx, binPath, args...)
	cmd.Dir = dir

	// Clean isolated environment: never taint developer's home or system npm caches
	env := os.Environ()
	env = append(env, envExtra...)
	cmd.Env = env

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err = cmd.Run()
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}

	return stdoutBuf.String(), stderrBuf.String(), exitCode, err
}

// IsolatedClientEnv configures environment variables routing registry requests to the gateway URL
// and pointing cache/config directories inside a temporary workspace.
func IsolatedClientEnv(tempDir, gatewayURL string) []string {
	cacheDir := filepath.Join(tempDir, ".client-cache")
	homeDir := filepath.Join(tempDir, ".client-home")
	_ = os.MkdirAll(cacheDir, 0o755)
	_ = os.MkdirAll(homeDir, 0o755)

	return []string{
		"HOME=" + homeDir,
		"USERPROFILE=" + homeDir,
		"NPM_CONFIG_REGISTRY=" + gatewayURL,
		"NPM_CONFIG_CACHE=" + cacheDir,
		"NPM_CONFIG_USERCONFIG=" + filepath.Join(tempDir, ".npmrc"),
		"PNPM_HOME=" + filepath.Join(tempDir, ".pnpm-home"),
		"YARN_CACHE_FOLDER=" + filepath.Join(tempDir, ".yarn-cache"),
		"BUN_INSTALL=" + filepath.Join(tempDir, ".bun"),
	}
}

// AssertInstalledPackage verifies that an installed dependency exists on disk,
// matches the expected version in package.json, and contains valid files.
func AssertInstalledPackage(t *testing.T, workDir, pkgName, expectedVersion string) {
	t.Helper()

	pkgDir := filepath.Join(workDir, "node_modules", filepath.FromSlash(pkgName))
	pkgJSONPath := filepath.Join(pkgDir, "package.json")

	data, err := os.ReadFile(pkgJSONPath)
	if err != nil {
		t.Fatalf("expected package %s installed at %s, but read failed: %v", pkgName, pkgJSONPath, err)
	}

	var parsed struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid package.json for %s: %v", pkgName, err)
	}

	if parsed.Name != pkgName {
		t.Errorf("installed package name mismatch: got %q, want %q", parsed.Name, pkgName)
	}
	if parsed.Version != expectedVersion {
		t.Errorf("installed package version mismatch for %s: got %q, want %q", pkgName, parsed.Version, expectedVersion)
	}

	// Verify index.js is present and uncorrupted
	indexPath := filepath.Join(pkgDir, "index.js")
	indexData, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatalf("missing index.js in %s: %v", pkgName, err)
	}
	if !bytes.Contains(indexData, []byte(pkgName)) {
		t.Errorf("index.js corrupted in %s: %s", pkgName, string(indexData))
	}
}

// AssertPnpmLinkedDependency verifies a package that pnpm resolved as a
// dependency of dependent — a peer, optional or ordinary transitive one.
//
// It deliberately does not look in the project's top-level node_modules.
// pnpm's virtual store holds every package at
// node_modules/.pnpm/<name>@<version>[_<peer-suffix>]/node_modules/<name> and
// links only *declared* dependencies where the project root can import them.
// Refusing to hoist is the feature pnpm exists for, so asserting npm's flat
// layout against a pnpm install tests that feature backwards: it fails when
// pnpm is working correctly, and would pass if pnpm started leaking phantom
// dependencies.
func AssertPnpmLinkedDependency(t *testing.T, workDir, dependent, dependentVersion, pkgName, expectedVersion string) {
	t.Helper()

	storeName := strings.ReplaceAll(dependent, "/", "+") + "@" + dependentVersion
	// The directory may carry a peer-resolution suffix, e.g.
	// fixture-peer@1.0.0_fixture-unscoped@1.0.0.
	pattern := filepath.Join(workDir, "node_modules", ".pnpm", storeName+"*", "node_modules", filepath.FromSlash(pkgName))
	matches, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatalf("globbing pnpm store for %s under %s: %v", pkgName, dependent, err)
	}
	if len(matches) == 0 {
		t.Fatalf("expected %s linked under %s in the pnpm store (%s), found nothing", pkgName, dependent, pattern)
	}

	assertPackageContents(t, matches[0], pkgName, expectedVersion)
}

// AssertNotHoisted verifies a package is absent from the project's top-level
// node_modules. Under pnpm this is a guarantee, not an accident: code that
// never declared the dependency must not be able to import it.
func AssertNotHoisted(t *testing.T, workDir, pkgName string) {
	t.Helper()

	path := filepath.Join(workDir, "node_modules", filepath.FromSlash(pkgName))
	if _, err := os.Lstat(path); err == nil {
		t.Errorf("%s is reachable at the project root (%s); an undeclared dependency must not be hoisted under pnpm", pkgName, path)
	} else if !os.IsNotExist(err) {
		t.Fatalf("checking %s is not hoisted: %v", pkgName, err)
	}
}

// assertPackageContents checks the package.json identity and the fixture's
// index.js payload for a package directory, wherever it lives on disk.
func assertPackageContents(t *testing.T, pkgDir, pkgName, expectedVersion string) {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(pkgDir, "package.json"))
	if err != nil {
		t.Fatalf("expected package %s at %s, but read failed: %v", pkgName, pkgDir, err)
	}

	var parsed struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("invalid package.json for %s: %v", pkgName, err)
	}
	if parsed.Name != pkgName {
		t.Errorf("installed package name mismatch: got %q, want %q", parsed.Name, pkgName)
	}
	if parsed.Version != expectedVersion {
		t.Errorf("installed package version mismatch for %s: got %q, want %q", pkgName, parsed.Version, expectedVersion)
	}

	indexData, err := os.ReadFile(filepath.Join(pkgDir, "index.js"))
	if err != nil {
		t.Fatalf("missing index.js in %s: %v", pkgName, err)
	}
	if !bytes.Contains(indexData, []byte(pkgName)) {
		t.Errorf("index.js corrupted in %s: %s", pkgName, string(indexData))
	}
}

// requirePackageManager skips a suite when the package manager is not
// installed, except where the environment declares that it must be.
//
// CI sets INSTALLGATE_REQUIRE_PACKAGE_MANAGERS=1. Without it a missing binary
// silently skips, and a silent skip on the runner is indistinguishable from a
// pass — which is how a compatibility matrix comes to claim coverage it does
// not have. The Bun setup step is `continue-on-error`, so this is not
// hypothetical.
func requirePackageManager(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err == nil {
		return
	}
	if os.Getenv("INSTALLGATE_REQUIRE_PACKAGE_MANAGERS") == "1" {
		t.Fatalf("%s is not on PATH, but INSTALLGATE_REQUIRE_PACKAGE_MANAGERS=1 declares this environment covers it; the matrix must not report coverage it does not have", name)
	}
	t.Skipf("%s is not installed on this host; this suite covers %s only where it is present", name, name)
}

// AssertWorkspaceDependencyResolvable verifies that a workspace member can
// resolve a dependency it declared, wherever the package manager chose to put
// it.
//
// The layout is not the contract. npm and Yarn hoist a workspace member's
// dependency to the root node_modules; pnpm links it from the virtual store;
// Bun may do either. Asserting one directory tests the package manager's
// layout rather than whether the gateway served the package, and fails on a
// manager that is behaving correctly.
//
// Node's own resolution algorithm walks node_modules upward from the importing
// file, so this checks the same chain: the member's own node_modules first,
// then each ancestor up to the workspace root. If none of them has it, the
// failure prints every place the package *was* found, because that is the
// information needed to tell a layout difference from a real install failure.
func AssertWorkspaceDependencyResolvable(t *testing.T, workspaceRoot, memberDir, pkgName, expectedVersion string) {
	t.Helper()

	dir := memberDir
	for {
		candidate := filepath.Join(dir, "node_modules", filepath.FromSlash(pkgName))
		if _, err := os.Stat(filepath.Join(candidate, "package.json")); err == nil {
			assertPackageContents(t, candidate, pkgName, expectedVersion)
			return
		}
		if dir == workspaceRoot {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	t.Errorf("%s is not resolvable from %s by walking node_modules up to %s", pkgName, memberDir, workspaceRoot)
	for _, found := range findPackageDirs(workspaceRoot, pkgName) {
		t.Logf("  found instead at: %s", strings.TrimPrefix(found, workspaceRoot))
	}
	t.FailNow()
}

// findPackageDirs reports every directory under root named pkgName, so a
// failure can say where the package manager actually put it.
func findPackageDirs(root, pkgName string) []string {
	var found []string
	base := filepath.Base(filepath.FromSlash(pkgName))
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() && d.Name() == base {
			found = append(found, path)
		}
		return nil
	})
	if len(found) == 0 {
		found = append(found, "(nowhere under the workspace root)")
	}
	return found
}
