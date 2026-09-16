package evidence

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aniklavida/installgate/internal/verdict"
)

const (
	DefaultOSVBaseURL = "https://api.osv.dev"
	DefaultTimeout    = 10 * time.Second
	DefaultMaxConns   = 10
)

var (
	errEmptyBody       = errors.New("upstream returned empty body: expected OSV JSON advisory payload")
	errNoVulnsKey      = errors.New(`upstream response omitted the "vulns" key: cannot tell an answer from a stub`)
	errProviderTimeout = errors.New("advisory provider request timed out")
)

// AdvisoryProvider queries OSV for vulnerability and malicious package records.
type AdvisoryProvider struct {
	name     string
	baseURL  string
	client   *http.Client
	timeout  time.Duration
	clock    func() time.Time
	freshTTL time.Duration
	sem      chan struct{}
}

// AdvisoryOption configures an AdvisoryProvider.
type AdvisoryOption func(*AdvisoryProvider)

// WithAdvisoryBaseURL overrides the default OSV API base URL.
func WithAdvisoryBaseURL(url string) AdvisoryOption {
	return func(p *AdvisoryProvider) {
		if url != "" {
			p.baseURL = strings.TrimSuffix(url, "/")
		}
	}
}

// WithAdvisoryHTTPClient sets a custom HTTP client.
func WithAdvisoryHTTPClient(client *http.Client) AdvisoryOption {
	return func(p *AdvisoryProvider) {
		if client != nil {
			p.client = client
		}
	}
}

// WithAdvisoryTimeout sets the query timeout.
func WithAdvisoryTimeout(timeout time.Duration) AdvisoryOption {
	return func(p *AdvisoryProvider) {
		if timeout > 0 {
			p.timeout = timeout
		}
	}
}

// WithAdvisoryClock sets a custom clock function for deterministic testing.
func WithAdvisoryClock(clock func() time.Time) AdvisoryOption {
	return func(p *AdvisoryProvider) {
		if clock != nil {
			p.clock = clock
		}
	}
}

// WithAdvisoryConcurrency limits concurrent outgoing requests.
func WithAdvisoryConcurrency(maxConns int) AdvisoryOption {
	return func(p *AdvisoryProvider) {
		if maxConns > 0 {
			p.sem = make(chan struct{}, maxConns)
		}
	}
}

// WithAdvisoryFreshTTL sets the fresh lifetime for retrieved advisories.
func WithAdvisoryFreshTTL(ttl time.Duration) AdvisoryOption {
	return func(p *AdvisoryProvider) {
		if ttl > 0 {
			p.freshTTL = ttl
		}
	}
}

// NewAdvisoryProvider constructs an OSV advisory provider.
func NewAdvisoryProvider(opts ...AdvisoryOption) *AdvisoryProvider {
	p := &AdvisoryProvider{
		name:     "osv",
		baseURL:  DefaultOSVBaseURL,
		timeout:  DefaultTimeout,
		freshTTL: 1 * time.Hour,
		sem:      make(chan struct{}, DefaultMaxConns),
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

func (p *AdvisoryProvider) Name() string {
	return p.name
}

func (p *AdvisoryProvider) Kind() string {
	return KindVulnerability
}

// OSV schema types
type osvPackageRef struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvSingleQuery struct {
	Package osvPackageRef `json:"package"`
	Version string        `json:"version"`
}

type osvBatchQueryPayload struct {
	Queries []osvSingleQuery `json:"queries"`
}

type osvEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvAffected struct {
	Package  osvPackageRef `json:"package"`
	Ranges   []osvRange    `json:"ranges"`
	Versions []string      `json:"versions"`
}

type osvVulnerability struct {
	ID               string                 `json:"id"`
	Summary          string                 `json:"summary"`
	Details          string                 `json:"details"`
	Aliases          []string               `json:"aliases"`
	DatabaseSpecific map[string]interface{} `json:"database_specific"`
	Affected         []osvAffected          `json:"affected"`
}

type osvQueryResponse struct {
	Vulns []osvVulnerability `json:"vulns"`
}

type osvBatchQueryResponse struct {
	Results []osvQueryResponse `json:"results"`
}

// hasVulnsKey reports whether an OSV response actually carried a "vulns" field.
//
// `{"vulns": []}` is OSV saying "we looked and found nothing" — a legitimate
// clean answer, and the ordinary response for a healthy package. `{}` omits the
// field altogether, and nothing in it distinguishes a real answer from a stub,
// a proxy's default body, or a truncated cache entry. Unmarshalling alone
// cannot tell them apart: both leave the slice empty. The first may allow; the
// second must never be read as an all-clear.
func hasVulnsKey(body []byte) bool {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return false
	}
	_, ok := raw["vulns"]
	return ok
}

// Provide queries OSV for the resolved package coordinates.
func (p *AdvisoryProvider) Provide(ctx context.Context, q Query) Outcome {
	now := p.now()

	select {
	case p.sem <- struct{}{}:
		defer func() { <-p.sem }()
	case <-ctx.Done():
		return NewUnavailableOutcome(p.Kind(), p.Name(), ctx.Err(), now)
	}

	reqPayload := osvSingleQuery{
		Package: osvPackageRef{
			Name:      q.Package,
			Ecosystem: "npm",
		},
		Version: q.Version,
	}

	jsonBytes, err := json.Marshal(reqPayload)
	if err != nil {
		return NewUnavailableOutcome(p.Kind(), p.Name(), fmt.Errorf("failed to marshal osv query: %w", err), now)
	}

	reqCtx := ctx
	var cancel context.CancelFunc
	if p.timeout > 0 {
		reqCtx, cancel = context.WithTimeout(ctx, p.timeout)
		defer cancel()
	}

	reqURL := fmt.Sprintf("%s/v1/query", p.baseURL)
	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, reqURL, bytes.NewReader(jsonBytes))
	if err != nil {
		return NewUnavailableOutcome(p.Kind(), p.Name(), err, now)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	client := p.client
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || (reqCtx.Err() != nil && errors.Is(reqCtx.Err(), context.DeadlineExceeded)) {
			return NewUnavailableOutcome(p.Kind(), p.Name(), errProviderTimeout, now)
		}
		return NewUnavailableOutcome(p.Kind(), p.Name(), err, now)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return NewUnavailableOutcome(p.Kind(), p.Name(), fmt.Errorf("upstream returned HTTP %d", resp.StatusCode), now)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return NewUnavailableOutcome(p.Kind(), p.Name(), fmt.Errorf("read error: %w", err), now)
	}

	// An empty body (0 bytes) must never be interpreted as safe or clean
	if len(bodyBytes) == 0 {
		return NewUnavailableOutcome(p.Kind(), p.Name(), errEmptyBody, now)
	}

	var parsed osvQueryResponse
	if err := json.Unmarshal(bodyBytes, &parsed); err != nil {
		return NewUnavailableOutcome(p.Kind(), p.Name(), fmt.Errorf("invalid json payload: %w", err), now)
	}

	if !hasVulnsKey(bodyBytes) {
		return NewUnavailableOutcome(p.Kind(), p.Name(), errNoVulnsKey, now)
	}

	freshUntil := now.Add(p.freshTTL)

	// Check if upstream signaled stale data
	isStale := false
	if warning := resp.Header.Get("Warning"); strings.Contains(warning, "110") {
		isStale = true
	}

	signals := p.processVulnerabilities(parsed.Vulns, now, freshUntil)

	if isStale {
		return NewStaleOutcome(p.Kind(), p.Name(), signals, now, now, "upstream returned stale advisory cache")
	}

	return NewAvailableOutcome(p.Kind(), p.Name(), signals, now, freshUntil)
}

// rawBatchResults returns each element of an OSV batch response's "results"
// array as raw JSON, so the presence of "vulns" can be tested per result.
func rawBatchResults(body []byte) []json.RawMessage {
	var raw struct {
		Results []json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil
	}
	return raw.Results
}

// ProvideBatch executes batch lookups using OSV's /v1/querybatch endpoint.
func (p *AdvisoryProvider) ProvideBatch(ctx context.Context, queries []Query) []Outcome {
	now := p.now()
	outcomes := make([]Outcome, len(queries))

	if len(queries) == 0 {
		return outcomes
	}

	select {
	case p.sem <- struct{}{}:
		defer func() { <-p.sem }()
	case <-ctx.Done():
		for i := range queries {
			outcomes[i] = NewUnavailableOutcome(p.Kind(), p.Name(), ctx.Err(), now)
		}
		return outcomes
	}

	batchPayload := osvBatchQueryPayload{
		Queries: make([]osvSingleQuery, len(queries)),
	}
	for i, q := range queries {
		batchPayload.Queries[i] = osvSingleQuery{
			Package: osvPackageRef{
				Name:      q.Package,
				Ecosystem: "npm",
			},
			Version: q.Version,
		}
	}

	jsonBytes, err := json.Marshal(batchPayload)
	if err != nil {
		for i := range queries {
			outcomes[i] = NewUnavailableOutcome(p.Kind(), p.Name(), err, now)
		}
		return outcomes
	}

	reqCtx := ctx
	var cancel context.CancelFunc
	if p.timeout > 0 {
		reqCtx, cancel = context.WithTimeout(ctx, p.timeout)
		defer cancel()
	}

	reqURL := fmt.Sprintf("%s/v1/querybatch", p.baseURL)
	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, reqURL, bytes.NewReader(jsonBytes))
	if err != nil {
		for i := range queries {
			outcomes[i] = NewUnavailableOutcome(p.Kind(), p.Name(), err, now)
		}
		return outcomes
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	client := p.client
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		for i := range queries {
			outcomes[i] = NewUnavailableOutcome(p.Kind(), p.Name(), err, now)
		}
		return outcomes
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errHttp := fmt.Errorf("upstream returned HTTP %d", resp.StatusCode)
		for i := range queries {
			outcomes[i] = NewUnavailableOutcome(p.Kind(), p.Name(), errHttp, now)
		}
		return outcomes
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		errRead := fmt.Errorf("read error: %w", err)
		for i := range queries {
			outcomes[i] = NewUnavailableOutcome(p.Kind(), p.Name(), errRead, now)
		}
		return outcomes
	}

	if len(bodyBytes) == 0 {
		for i := range queries {
			outcomes[i] = NewUnavailableOutcome(p.Kind(), p.Name(), errEmptyBody, now)
		}
		return outcomes
	}

	var parsed osvBatchQueryResponse
	if err := json.Unmarshal(bodyBytes, &parsed); err != nil {
		errParse := fmt.Errorf("invalid json payload: %w", err)
		for i := range queries {
			outcomes[i] = NewUnavailableOutcome(p.Kind(), p.Name(), errParse, now)
		}
		return outcomes
	}

	if len(parsed.Results) != len(queries) {
		errMismatch := fmt.Errorf("batch results count mismatch: expected %d, got %d", len(queries), len(parsed.Results))
		for i := range queries {
			outcomes[i] = NewUnavailableOutcome(p.Kind(), p.Name(), errMismatch, now)
		}
		return outcomes
	}

	freshUntil := now.Add(p.freshTTL)
	isStale := strings.Contains(resp.Header.Get("Warning"), "110")

	// Same rule as the single-query path, applied per result: a result object
	// that omits "vulns" is not an all-clear. ProvideBatch has no production
	// caller today; the check goes in now so it is not a hole waiting for one.
	rawResults := rawBatchResults(bodyBytes)

	for i, res := range parsed.Results {
		if i >= len(rawResults) || !hasVulnsKey(rawResults[i]) {
			outcomes[i] = NewUnavailableOutcome(p.Kind(), p.Name(), errNoVulnsKey, now)
			continue
		}
		sigs := p.processVulnerabilities(res.Vulns, now, freshUntil)
		if isStale {
			outcomes[i] = NewStaleOutcome(p.Kind(), p.Name(), sigs, now, now, "upstream returned stale advisory cache")
		} else {
			outcomes[i] = NewAvailableOutcome(p.Kind(), p.Name(), sigs, now, freshUntil)
		}
	}

	return outcomes
}

func (p *AdvisoryProvider) processVulnerabilities(vulns []osvVulnerability, now, freshUntil time.Time) []verdict.Signal {
	var signals []verdict.Signal

	if len(vulns) == 0 {
		// Absence of an advisory is explicitly recorded as "no record found at this retrieval time",
		// NEVER as evidence of safety.
		return []verdict.Signal{
			{
				Kind:        p.Kind(),
				Source:      p.Name(),
				Observation: "no_record_found",
				Confidence:  ConfidenceMedium,
				RetrievedAt: now,
				FreshUntil:  freshUntil,
			},
		}
	}

	var hasMalicious bool
	var safeVersion string

	for _, v := range vulns {
		isMal := isMaliciousRecord(v)
		if isMal {
			hasMalicious = true
			signals = append(signals, verdict.Signal{
				Kind:        KindMalicious,
				Source:      p.Name(),
				Observation: "malicious",
				Confidence:  ConfidenceHigh,
				RetrievedAt: now,
				FreshUntil:  freshUntil,
			})
			signals = append(signals, verdict.Signal{
				Kind:        p.Kind(),
				Source:      p.Name(),
				Observation: "malicious",
				Confidence:  ConfidenceHigh,
				RetrievedAt: now,
				FreshUntil:  freshUntil,
			})
		} else {
			// Ordinary vulnerability
			signals = append(signals, verdict.Signal{
				Kind:        p.Kind(),
				Source:      p.Name(),
				Observation: "above_threshold",
				Confidence:  ConfidenceHigh,
				RetrievedAt: now,
				FreshUntil:  freshUntil,
			})
		}

		if fixed := extractFixedVersion(v); fixed != "" && safeVersion == "" {
			safeVersion = fixed
		}
	}

	// If verified safe fixed version exists, offer it as an informational recommendation
	if safeVersion != "" && !hasMalicious {
		signals = append(signals, verdict.Signal{
			Kind:        p.Kind(),
			Source:      p.Name(),
			Observation: fmt.Sprintf("safe_version_suggested:%s", safeVersion),
			Confidence:  ConfidenceHigh,
			RetrievedAt: now,
			FreshUntil:  freshUntil,
		})
	}

	return signals
}

func isMaliciousRecord(v osvVulnerability) bool {
	idUpper := strings.ToUpper(v.ID)
	if strings.HasPrefix(idUpper, "MAL-") {
		return true
	}
	for _, alias := range v.Aliases {
		if strings.HasPrefix(strings.ToUpper(alias), "MAL-") {
			return true
		}
	}
	if v.DatabaseSpecific != nil {
		if mal, ok := v.DatabaseSpecific["malicious"].(bool); ok && mal {
			return true
		}
		if malStr, ok := v.DatabaseSpecific["malicious"].(string); ok && strings.EqualFold(malStr, "true") {
			return true
		}
	}
	lowerSummary := strings.ToLower(v.Summary)
	lowerDetails := strings.ToLower(v.Details)
	if strings.Contains(lowerSummary, "malicious package") || strings.Contains(lowerSummary, "malware") ||
		strings.Contains(lowerDetails, "malicious package") || strings.Contains(lowerDetails, "malware") {
		return true
	}
	return false
}

func extractFixedVersion(v osvVulnerability) string {
	for _, aff := range v.Affected {
		for _, r := range aff.Ranges {
			for _, ev := range r.Events {
				if ev.Fixed != "" {
					return ev.Fixed
				}
			}
		}
	}
	return ""
}

func (p *AdvisoryProvider) now() time.Time {
	if p.clock != nil {
		return normalizeTime(p.clock())
	}
	return normalizeTime(time.Now())
}
