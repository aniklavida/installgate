package config

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/aniklavida/installgate/internal/evidence"
)

// DefaultGatewayPort is the default local listening port for the InstallGate service.
const DefaultGatewayPort = 8765

// DefaultGatewayURL is the default base URL for the local gateway.
const DefaultGatewayURL = "http://127.0.0.1:8765"

// StatusReport details the current lifecycle, operational, and cache freshness state.
type StatusReport struct {
	GatewayRunning bool                `json:"gateway_running"`
	GatewayURL     string              `json:"gateway_url"`
	Port           int                 `json:"port"`
	PID            int                 `json:"pid,omitempty"`
	NpmEnabled     bool                `json:"npm_enabled"`
	NpmrcPath      string              `json:"npmrc_path"`
	ActiveRegistry string              `json:"active_registry"`
	PriorRegistry  string              `json:"prior_registry,omitempty"`
	CacheStats     evidence.CacheStats `json:"cache"`
	RecoveryNote   string              `json:"recovery_note,omitempty"`
}

// HealthChecker probes a gateway URL for readiness and health status.
type HealthChecker func(ctx context.Context, gatewayURL string) (*HealthResponse, error)

// HealthResponse holds the parsed response from the gateway health route.
type HealthResponse struct {
	Status string              `json:"status"`
	Ready  bool                `json:"ready"`
	Cache  evidence.CacheStats `json:"cache"`
}

// Option configures a LifecycleManager instance.
type Option func(*LifecycleManager)

// WithDataDir sets the root data directory for state and transaction logs.
func WithDataDir(dir string) Option {
	return func(m *LifecycleManager) {
		m.dataDir = dir
	}
}

// WithNpmrcPath sets the target .npmrc file path.
func WithNpmrcPath(path string) Option {
	return func(m *LifecycleManager) {
		m.npmrcPath = path
	}
}

// WithGatewayURL sets the expected gateway base URL.
func WithGatewayURL(urlStr string) Option {
	return func(m *LifecycleManager) {
		m.gatewayURL = strings.TrimSuffix(urlStr, "/")
	}
}

// WithGatewayPort sets the expected gateway local port.
func WithGatewayPort(port int) Option {
	return func(m *LifecycleManager) {
		m.gatewayPort = port
	}
}

// WithStore sets an explicit StateStore implementation.
func WithStore(store StateStore) Option {
	return func(m *LifecycleManager) {
		m.store = store
	}
}

// WithHealthChecker sets a custom health checker function.
func WithHealthChecker(checker HealthChecker) Option {
	return func(m *LifecycleManager) {
		m.healthChecker = checker
	}
}

// WithPreCommitHook sets a hook called immediately before atomic rename in transactions.
// Used exclusively in tests to simulate mid-write crash/interruption.
func WithPreCommitHook(hook func()) Option {
	return func(m *LifecycleManager) {
		m.preCommitHook = hook
	}
}

// LifecycleManager manages the InstallGate service lifecycle, atomic npm registry configuration,
// and transaction recovery.
type LifecycleManager struct {
	dataDir       string
	npmrcPath     string
	gatewayURL    string
	gatewayPort   int
	store         StateStore
	healthChecker HealthChecker
	preCommitHook func()
}

// NewLifecycleManager constructs a LifecycleManager with validated settings.
func NewLifecycleManager(opts ...Option) (*LifecycleManager, error) {
	m := &LifecycleManager{
		gatewayURL:  DefaultGatewayURL,
		gatewayPort: DefaultGatewayPort,
	}

	if envPort := os.Getenv("INSTALLGATE_PORT"); envPort != "" {
		if p, err := strconv.Atoi(envPort); err == nil && p > 0 {
			m.gatewayPort = p
			m.gatewayURL = fmt.Sprintf("http://127.0.0.1:%d", p)
		}
	}
	if envURL := os.Getenv("INSTALLGATE_GATEWAY_URL"); envURL != "" {
		m.gatewayURL = strings.TrimSuffix(envURL, "/")
	}

	for _, opt := range opts {
		opt(m)
	}

	if m.dataDir == "" {
		if env := os.Getenv("INSTALLGATE_DATA_DIR"); env != "" {
			m.dataDir = env
		} else if home, err := os.UserHomeDir(); err == nil && home != "" {
			m.dataDir = filepath.Join(home, ".installgate")
		} else {
			m.dataDir = ".installgate"
		}
	}

	if m.npmrcPath == "" {
		m.npmrcPath = DefaultNpmrcPath()
	}

	if m.store == nil {
		store, err := NewFileStateStore(m.dataDir)
		if err != nil {
			return nil, err
		}
		m.store = store
	}

	if m.healthChecker == nil {
		m.healthChecker = defaultHealthChecker
	}

	return m, nil
}

func defaultHealthChecker(ctx context.Context, gatewayURL string) (*HealthResponse, error) {
	healthURL := ensureTrailingSlash(gatewayURL) + "-/installgate/health"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gateway returned status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var hr HealthResponse
	if err := json.Unmarshal(data, &hr); err != nil {
		return nil, fmt.Errorf("failed to decode health response: %w", err)
	}

	return &hr, nil
}

// Init initializes the environment directories and verifies health.
func (m *LifecycleManager) Init(ctx context.Context) error {
	if err := os.MkdirAll(m.dataDir, 0o700); err != nil {
		return fmt.Errorf("failed to initialize data directory: %w", err)
	}

	// Recover any pending transaction journal from prior interruption
	_, _ = RecoverJournal(m.store)

	return nil
}

// EnableNpm configures npm to route package requests through InstallGate.
// Invariant: There is NO WINDOW in which npm points at a gateway that is not running.
func (m *LifecycleManager) EnableNpm(ctx context.Context) error {
	// 1. Recover any interrupted journal first
	_, _ = RecoverJournal(m.store)

	// 2. Inspect target .npmrc and validate compatibility
	info, err := InspectNpmrc(m.npmrcPath)
	if err != nil {
		return err
	}

	// 3. Ensure gateway is actually running and healthy before modifying configuration
	hr, err := m.healthChecker(ctx, m.gatewayURL)
	if err != nil || hr == nil || !hr.Ready {
		return fmt.Errorf("cannot enable npm: InstallGate gateway is not running or not ready at %s. Start the gateway before enabling npm", m.gatewayURL)
	}

	// 4. Capture prior configuration for exact restoration
	prior := PriorConfig{
		FileExisted:   info.Exists,
		HasRegistry:   info.HasRegistry,
		RegistryValue: info.RegistryValue,
		RawContent:    info.RawContent,
	}

	// 5. Generate new content pointing to gateway
	newContent := GenerateEnabledContent(info, m.gatewayURL)

	// 6. Begin transaction in durable journal
	tx, err := BeginTransaction(m.store, ActionEnable, m.npmrcPath, m.gatewayURL, prior)
	if err != nil {
		return err
	}

	// 7. Stage new content to sibling temp file
	if _, err := StageTransaction(m.store, tx, newContent); err != nil {
		return err
	}

	// 8. Commit transaction atomically
	if err := CommitTransaction(m.store, tx, m.preCommitHook); err != nil {
		return err
	}

	return nil
}

// DisableNpm cleanly restores the developer's exact prior npm registry configuration.
// Constraint: Disable is the feature. Restore byte-for-byte, including when no value was set.
func (m *LifecycleManager) DisableNpm(ctx context.Context) error {
	// 1. Recover any interrupted journal first
	_, _ = RecoverJournal(m.store)

	// 2. Determine prior configuration
	state, err := m.store.LoadState()
	if err != nil {
		return fmt.Errorf("failed to load state: %w", err)
	}

	var prior PriorConfig
	if state != nil && state.PriorConfig != nil {
		prior = *state.PriorConfig
	} else {
		// If prior state is missing, inspect existing file to safely revert gateway setting
		info, err := InspectNpmrc(m.npmrcPath)
		if err != nil {
			return err
		}
		if !info.Exists {
			return nil // Already no file, nothing to do
		}
		// If gateway was pointing here, fallback to public registry
		prior = PriorConfig{
			FileExisted:   true,
			HasRegistry:   true,
			RegistryValue: "https://registry.npmjs.org/",
			RawContent:    []byte("registry=https://registry.npmjs.org/\n"),
		}
	}

	// 3. Begin disable transaction
	tx, err := BeginTransaction(m.store, ActionDisable, m.npmrcPath, m.gatewayURL, prior)
	if err != nil {
		return err
	}

	// 4. Stage restored content if prior file existed
	if prior.FileExisted {
		if _, err := StageTransaction(m.store, tx, prior.RawContent); err != nil {
			return err
		}
	}

	// 5. Commit disable transaction
	if err := CommitTransaction(m.store, tx, m.preCommitHook); err != nil {
		return err
	}

	return nil
}

// Status inspects and truthfully reports gateway process, npm configuration, and cache freshness.
func (m *LifecycleManager) Status(ctx context.Context) (*StatusReport, error) {
	// Check for any active journal recovery
	var recoveryNote string
	rec, err := RecoverJournal(m.store)
	if err != nil {
		recoveryNote = fmt.Sprintf("recovery error: %v", err)
	} else if rec != nil {
		recoveryNote = rec.Message
	}

	report := &StatusReport{
		GatewayURL: m.gatewayURL,
		Port:       m.gatewayPort,
		NpmrcPath:  m.npmrcPath,
	}
	if recoveryNote != "" {
		report.RecoveryNote = recoveryNote
	}

	// Check gateway health and cache freshness
	hr, err := m.healthChecker(ctx, m.gatewayURL)
	if err == nil && hr != nil && hr.Ready {
		report.GatewayRunning = true
		report.CacheStats = hr.Cache
	}

	// Inspect .npmrc
	info, err := InspectNpmrc(m.npmrcPath)
	if err == nil {
		if info.HasRegistry {
			report.ActiveRegistry = info.RegistryValue
			normActive := strings.TrimSuffix(info.RegistryValue, "/")
			normGw := strings.TrimSuffix(m.gatewayURL, "/")
			if normActive == normGw {
				report.NpmEnabled = true
			}
		} else if info.Exists {
			report.ActiveRegistry = "(default public registry: https://registry.npmjs.org/)"
		} else {
			report.ActiveRegistry = "(no .npmrc file; defaults to https://registry.npmjs.org/)"
		}
	}

	// Check stored prior config
	state, _ := m.store.LoadState()
	if state != nil && state.PriorConfig != nil {
		if state.PriorConfig.HasRegistry {
			report.PriorRegistry = state.PriorConfig.RegistryValue
		} else {
			report.PriorRegistry = "(none)"
		}
		if state.PID > 0 {
			report.PID = state.PID
		}
	}

	return report, nil
}
