package evidence

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/aniklavida/installgate/internal/verdict"
)

var (
	errEmptyProvenanceBody = errors.New("upstream returned empty body: expected npm packument JSON")
	errProvenanceTimeout   = errors.New("provenance provider request timed out")
)

// ProvenanceProvider inspects maintainer set changes, publisher changes,
// repository field changes, and provenance attestation presence or removal.
type ProvenanceProvider struct {
	name        string
	registryURL string
	client      *http.Client
	timeout     time.Duration
	clock       func() time.Time
	freshTTL    time.Duration
	sem         chan struct{}
}

// ProvenanceOption configures a ProvenanceProvider.
type ProvenanceOption func(*ProvenanceProvider)

// WithProvenanceRegistryURL overrides the default registry URL.
func WithProvenanceRegistryURL(registryURL string) ProvenanceOption {
	return func(p *ProvenanceProvider) {
		if registryURL != "" {
			p.registryURL = strings.TrimSuffix(registryURL, "/")
		}
	}
}

// WithProvenanceHTTPClient sets a custom HTTP client.
func WithProvenanceHTTPClient(client *http.Client) ProvenanceOption {
	return func(p *ProvenanceProvider) {
		if client != nil {
			p.client = client
		}
	}
}

// WithProvenanceTimeout sets the query timeout.
func WithProvenanceTimeout(timeout time.Duration) ProvenanceOption {
	return func(p *ProvenanceProvider) {
		if timeout > 0 {
			p.timeout = timeout
		}
	}
}

// WithProvenanceClock sets a custom clock function for deterministic testing.
func WithProvenanceClock(clock func() time.Time) ProvenanceOption {
	return func(p *ProvenanceProvider) {
		if clock != nil {
			p.clock = clock
		}
	}
}

// WithProvenanceConcurrency limits concurrent outgoing requests.
func WithProvenanceConcurrency(maxConns int) ProvenanceOption {
	return func(p *ProvenanceProvider) {
		if maxConns > 0 {
			p.sem = make(chan struct{}, maxConns)
		}
	}
}

// NewProvenanceProvider constructs an npm provenance evidence provider.
func NewProvenanceProvider(opts ...ProvenanceOption) *ProvenanceProvider {
	p := &ProvenanceProvider{
		name:        "npm_provenance",
		registryURL: DefaultRegistryURL,
		timeout:     DefaultTimeout,
		freshTTL:    6 * time.Hour,
		sem:         make(chan struct{}, DefaultMaxConns),
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

func (p *ProvenanceProvider) Name() string {
	return p.name
}

func (p *ProvenanceProvider) Kind() string {
	return KindProvenance
}

type npmUserMeta struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

type npmDistMeta struct {
	Integrity    string      `json:"integrity"`
	Tarball      string      `json:"tarball"`
	Attestations interface{} `json:"attestations"`
	Signatures   interface{} `json:"signatures"`
}

type npmVersionProvenanceMeta struct {
	Version     string        `json:"version"`
	Maintainers []npmUserMeta `json:"maintainers"`
	NpmUser     npmUserMeta   `json:"_npmUser"`
	Repository  interface{}   `json:"repository"`
	Dist        npmDistMeta   `json:"dist"`
}

type packumentProvenanceDoc struct {
	Name        string                              `json:"name"`
	Time        map[string]string                   `json:"time"`
	Maintainers []npmUserMeta                       `json:"maintainers"`
	Versions    map[string]npmVersionProvenanceMeta `json:"versions"`
}

// Provide queries registry metadata to evaluate provenance and maintainer continuity.
func (p *ProvenanceProvider) Provide(ctx context.Context, q Query) Outcome {
	now := p.now()

	select {
	case p.sem <- struct{}{}:
		defer func() { <-p.sem }()
	case <-ctx.Done():
		return NewUnavailableOutcome(p.Kind(), p.Name(), ctx.Err(), now)
	}

	reqCtx := ctx
	var cancel context.CancelFunc
	if p.timeout > 0 {
		reqCtx, cancel = context.WithTimeout(ctx, p.timeout)
		defer cancel()
	}

	var encodedPkg string
	if strings.HasPrefix(q.Package, "@") {
		encodedPkg = url.PathEscape(q.Package)
	} else {
		encodedPkg = q.Package
	}

	reqURL := fmt.Sprintf("%s/%s", p.registryURL, encodedPkg)
	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodGet, reqURL, nil)
	if err != nil {
		return NewUnavailableOutcome(p.Kind(), p.Name(), err, now)
	}
	httpReq.Header.Set("Accept", "application/json")

	client := p.client
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || (reqCtx.Err() != nil && errors.Is(reqCtx.Err(), context.DeadlineExceeded)) {
			return NewUnavailableOutcome(p.Kind(), p.Name(), errProvenanceTimeout, now)
		}
		return NewUnavailableOutcome(p.Kind(), p.Name(), err, now)
	}
	defer resp.Body.Close()

	freshUntil := now.Add(p.freshTTL)

	// Nonexistent package: 404
	if resp.StatusCode == http.StatusNotFound {
		sigs := []verdict.Signal{
			{
				Kind:        KindProvenance,
				Source:      p.Name(),
				Observation: "not_found",
				Confidence:  ConfidenceHigh,
				RetrievedAt: now,
				FreshUntil:  freshUntil,
			},
		}
		return NewAvailableOutcome(p.Kind(), p.Name(), sigs, now, freshUntil)
	}

	if resp.StatusCode != http.StatusOK {
		return NewUnavailableOutcome(p.Kind(), p.Name(), fmt.Errorf("upstream returned HTTP %d", resp.StatusCode), now)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return NewUnavailableOutcome(p.Kind(), p.Name(), fmt.Errorf("read error: %w", err), now)
	}

	if len(bodyBytes) == 0 {
		return NewUnavailableOutcome(p.Kind(), p.Name(), errEmptyProvenanceBody, now)
	}

	var doc packumentProvenanceDoc
	if err := json.Unmarshal(bodyBytes, &doc); err != nil {
		return NewUnavailableOutcome(p.Kind(), p.Name(), fmt.Errorf("invalid json payload: %w", err), now)
	}

	isStale := strings.Contains(resp.Header.Get("Warning"), "110")

	// Target version metadata
	currentVer, hasVer := doc.Versions[q.Version]
	if !hasVer {
		sigs := []verdict.Signal{
			{
				Kind:        KindProvenance,
				Source:      p.Name(),
				Observation: "version_not_found",
				Confidence:  ConfidenceHigh,
				RetrievedAt: now,
				FreshUntil:  freshUntil,
			},
		}
		if isStale {
			return NewStaleOutcome(p.Kind(), p.Name(), sigs, now, now, "upstream returned stale provenance cache")
		}
		return NewAvailableOutcome(p.Kind(), p.Name(), sigs, now, freshUntil)
	}

	// Determine chronological predecessor version
	prevVersion := p.findPreviousVersion(doc.Time, q.Version)

	var signals []verdict.Signal
	var changesDetected []string

	// Attestation check for current version
	currHasAttestation := hasAttestation(currentVer.Dist)
	if currHasAttestation {
		signals = append(signals, verdict.Signal{
			Kind:        KindProvenance,
			Source:      p.Name(),
			Observation: "attestation_present",
			Confidence:  ConfidenceHigh,
			RetrievedAt: now,
			FreshUntil:  freshUntil,
		})
	}

	if prevVersion == "" {
		// First/initial release
		signals = append(signals, verdict.Signal{
			Kind:        KindProvenance,
			Source:      p.Name(),
			Observation: "initial_release",
			Confidence:  ConfidenceHigh,
			RetrievedAt: now,
			FreshUntil:  freshUntil,
		})
	} else {
		prevVer, hasPrev := doc.Versions[prevVersion]
		if !hasPrev {
			// Previous version referenced in time is missing from versions map -> degraded
			sigs := []verdict.Signal{
				{
					Kind:        KindProvenance,
					Source:      p.Name(),
					Observation: "conflicting_metadata",
					Confidence:  ConfidenceLow,
					RetrievedAt: now,
					FreshUntil:  freshUntil,
				},
			}
			return NewDegradedOutcome(p.Kind(), p.Name(), sigs, now, freshUntil, "previous version in timeline missing from versions map")
		}

		// 1. Maintainer set change check
		currMaintainers := extractMaintainerNames(currentVer.Maintainers, doc.Maintainers)
		prevMaintainers := extractMaintainerNames(prevVer.Maintainers, doc.Maintainers)
		if !equalStringSet(currMaintainers, prevMaintainers) {
			changesDetected = append(changesDetected, "maintainer_set_changed")
		}

		// 2. Publisher change check
		if currentVer.NpmUser.Name != "" && prevVer.NpmUser.Name != "" {
			if currentVer.NpmUser.Name != prevVer.NpmUser.Name {
				// Publisher changed. If new publisher is not even in previous maintainer set:
				if !containsString(prevMaintainers, currentVer.NpmUser.Name) {
					changesDetected = append(changesDetected, "new_unrecognized_publisher")
				} else {
					changesDetected = append(changesDetected, "publisher_changed")
				}
			}
		}

		// 3. Repository field change check
		currRepo := extractRepoURL(currentVer.Repository)
		prevRepo := extractRepoURL(prevVer.Repository)
		if prevRepo != "" && currRepo != prevRepo {
			changesDetected = append(changesDetected, "repository_changed")
		}

		// 4. Provenance attestation removal check
		prevHasAttestation := hasAttestation(prevVer.Dist)
		if prevHasAttestation && !currHasAttestation {
			changesDetected = append(changesDetected, "attestation_removed")
			signals = append(signals, verdict.Signal{
				Kind:        KindProvenance,
				Source:      p.Name(),
				Observation: "attestation_removed",
				Confidence:  ConfidenceHigh,
				RetrievedAt: now,
				FreshUntil:  freshUntil,
			})
		}

		if len(changesDetected) > 0 {
			// Emit primary "changed" observation recognized by policy
			signals = append(signals, verdict.Signal{
				Kind:        KindProvenance,
				Source:      p.Name(),
				Observation: "changed",
				Confidence:  ConfidenceHigh,
				RetrievedAt: now,
				FreshUntil:  freshUntil,
			})
			for _, chg := range changesDetected {
				signals = append(signals, verdict.Signal{
					Kind:        KindProvenance,
					Source:      p.Name(),
					Observation: chg,
					Confidence:  ConfidenceHigh,
					RetrievedAt: now,
					FreshUntil:  freshUntil,
				})
			}
		} else {
			signals = append(signals, verdict.Signal{
				Kind:        KindProvenance,
				Source:      p.Name(),
				Observation: "unchanged",
				Confidence:  ConfidenceHigh,
				RetrievedAt: now,
				FreshUntil:  freshUntil,
			})
		}
	}

	if isStale {
		return NewStaleOutcome(p.Kind(), p.Name(), signals, now, now, "upstream returned stale provenance cache")
	}

	return NewAvailableOutcome(p.Kind(), p.Name(), signals, now, freshUntil)
}

func (p *ProvenanceProvider) findPreviousVersion(timeMap map[string]string, currentVersion string) string {
	if timeMap == nil {
		return ""
	}

	type verTime struct {
		version string
		t       time.Time
	}

	var timeline []verTime
	for v, tStr := range timeMap {
		if v == "created" || v == "modified" {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, tStr)
		if err == nil {
			timeline = append(timeline, verTime{version: v, t: t})
		}
	}

	sort.Slice(timeline, func(i, j int) bool {
		return timeline[i].t.Before(timeline[j].t)
	})

	for i, entry := range timeline {
		if entry.version == currentVersion {
			if i > 0 {
				return timeline[i-1].version
			}
			return ""
		}
	}

	return ""
}

func hasAttestation(d npmDistMeta) bool {
	if d.Attestations != nil {
		if m, ok := d.Attestations.(map[string]interface{}); ok && len(m) > 0 {
			return true
		}
		if s, ok := d.Attestations.(string); ok && s != "" {
			return true
		}
	}
	if d.Signatures != nil {
		if arr, ok := d.Signatures.([]interface{}); ok && len(arr) > 0 {
			return true
		}
	}
	return false
}

func extractMaintainerNames(versionMaintainers, docMaintainers []npmUserMeta) []string {
	var list []npmUserMeta
	if len(versionMaintainers) > 0 {
		list = versionMaintainers
	} else {
		list = docMaintainers
	}
	res := make([]string, 0, len(list))
	for _, m := range list {
		if m.Name != "" {
			res = append(res, strings.ToLower(m.Name))
		}
	}
	sort.Strings(res)
	return res
}

func extractRepoURL(repo interface{}) string {
	if repo == nil {
		return ""
	}
	if s, ok := repo.(string); ok {
		return normalizeRepoURL(s)
	}
	if m, ok := repo.(map[string]interface{}); ok {
		if u, ok := m["url"].(string); ok {
			return normalizeRepoURL(u)
		}
	}
	return ""
}

func normalizeRepoURL(u string) string {
	cleaned := strings.TrimSpace(u)
	cleaned = strings.TrimPrefix(cleaned, "git+")
	cleaned = strings.TrimPrefix(cleaned, "git://")
	cleaned = strings.TrimPrefix(cleaned, "ssh://git@")
	cleaned = strings.TrimSuffix(cleaned, ".git")
	return strings.ToLower(cleaned)
}

func equalStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func containsString(slice []string, val string) bool {
	valLower := strings.ToLower(val)
	for _, s := range slice {
		if s == valLower {
			return true
		}
	}
	return false
}

func (p *ProvenanceProvider) now() time.Time {
	if p.clock != nil {
		return normalizeTime(p.clock())
	}
	return normalizeTime(time.Now())
}
