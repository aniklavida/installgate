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

const (
	DefaultRegistryURL      = "https://registry.npmjs.org"
	DefaultNewbornThreshold = 7 * 24 * time.Hour
	DefaultFreshThreshold   = 24 * time.Hour
	DefaultDormantThreshold = 180 * 24 * time.Hour
)

var (
	errEmptyHistoryBody = errors.New("upstream returned empty body: expected npm packument JSON")
	errHistoryTimeout   = errors.New("history provider request timed out")
)

// HistoryProvider queries npm metadata to evaluate publish history, timelines,
// package age, and dormant-release revivals.
type HistoryProvider struct {
	name             string
	registryURL      string
	client           *http.Client
	timeout          time.Duration
	clock            func() time.Time
	freshTTL         time.Duration
	newbornThreshold time.Duration
	freshThreshold   time.Duration
	dormantThreshold time.Duration
	sem              chan struct{}
}

// HistoryOption configures a HistoryProvider.
type HistoryOption func(*HistoryProvider)

// WithHistoryRegistryURL overrides the default registry URL.
func WithHistoryRegistryURL(registryURL string) HistoryOption {
	return func(p *HistoryProvider) {
		if registryURL != "" {
			p.registryURL = strings.TrimSuffix(registryURL, "/")
		}
	}
}

// WithHistoryHTTPClient sets a custom HTTP client.
func WithHistoryHTTPClient(client *http.Client) HistoryOption {
	return func(p *HistoryProvider) {
		if client != nil {
			p.client = client
		}
	}
}

// WithHistoryTimeout sets the query timeout.
func WithHistoryTimeout(timeout time.Duration) HistoryOption {
	return func(p *HistoryProvider) {
		if timeout > 0 {
			p.timeout = timeout
		}
	}
}

// WithHistoryClock sets a custom clock function for deterministic testing.
func WithHistoryClock(clock func() time.Time) HistoryOption {
	return func(p *HistoryProvider) {
		if clock != nil {
			p.clock = clock
		}
	}
}

// WithHistoryConcurrency limits concurrent outgoing requests.
func WithHistoryConcurrency(maxConns int) HistoryOption {
	return func(p *HistoryProvider) {
		if maxConns > 0 {
			p.sem = make(chan struct{}, maxConns)
		}
	}
}

// WithNewbornThreshold sets the threshold below which a package is considered newborn.
func WithNewbornThreshold(d time.Duration) HistoryOption {
	return func(p *HistoryProvider) {
		if d > 0 {
			p.newbornThreshold = d
		}
	}
}

// WithFreshThreshold sets the threshold below which a version is considered fresh.
func WithFreshThreshold(d time.Duration) HistoryOption {
	return func(p *HistoryProvider) {
		if d > 0 {
			p.freshThreshold = d
		}
	}
}

// WithDormantThreshold sets the gap threshold for dormant-release revival.
func WithDormantThreshold(d time.Duration) HistoryOption {
	return func(p *HistoryProvider) {
		if d > 0 {
			p.dormantThreshold = d
		}
	}
}

// NewHistoryProvider constructs an npm history evidence provider.
func NewHistoryProvider(opts ...HistoryOption) *HistoryProvider {
	p := &HistoryProvider{
		name:             "npm_history",
		registryURL:      DefaultRegistryURL,
		timeout:          DefaultTimeout,
		freshTTL:         15 * time.Minute,
		newbornThreshold: DefaultNewbornThreshold,
		freshThreshold:   DefaultFreshThreshold,
		dormantThreshold: DefaultDormantThreshold,
		sem:              make(chan struct{}, DefaultMaxConns),
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

func (p *HistoryProvider) Name() string {
	return p.name
}

func (p *HistoryProvider) Kind() string {
	return KindPublishHistory
}

type packumentTimeDoc struct {
	Name     string                 `json:"name"`
	Time     map[string]string      `json:"time"`
	Versions map[string]interface{} `json:"versions"`
}

// Provide queries registry metadata and computes publish history observations.
func (p *HistoryProvider) Provide(ctx context.Context, q Query) Outcome {
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
			return NewUnavailableOutcome(p.Kind(), p.Name(), errHistoryTimeout, now)
		}
		return NewUnavailableOutcome(p.Kind(), p.Name(), err, now)
	}
	defer resp.Body.Close()

	freshUntil := now.Add(p.freshTTL)

	// HTTP 404: Package does not exist in registry.
	// Hard constraint: A nonexistent package fails as nonexistent and is NEVER labelled malicious.
	if resp.StatusCode == http.StatusNotFound {
		sigs := []verdict.Signal{
			{
				Kind:        KindPublishHistory,
				Source:      p.Name(),
				Observation: "not_found",
				Confidence:  ConfidenceHigh,
				RetrievedAt: now,
				FreshUntil:  freshUntil,
			},
			{
				Kind:        KindPackageAge,
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

	// 0-byte body must be treated as unavailable, never as a clean allow
	if len(bodyBytes) == 0 {
		return NewUnavailableOutcome(p.Kind(), p.Name(), errEmptyHistoryBody, now)
	}

	var doc packumentTimeDoc
	if err := json.Unmarshal(bodyBytes, &doc); err != nil {
		return NewUnavailableOutcome(p.Kind(), p.Name(), fmt.Errorf("invalid json payload: %w", err), now)
	}

	isStale := strings.Contains(resp.Header.Get("Warning"), "110")

	// Version existence check
	if doc.Versions != nil {
		if _, ok := doc.Versions[q.Version]; !ok {
			sigs := []verdict.Signal{
				{
					Kind:        KindPublishHistory,
					Source:      p.Name(),
					Observation: "version_not_found",
					Confidence:  ConfidenceHigh,
					RetrievedAt: now,
					FreshUntil:  freshUntil,
				},
				{
					Kind:        KindPackageAge,
					Source:      p.Name(),
					Observation: "version_not_found",
					Confidence:  ConfidenceHigh,
					RetrievedAt: now,
					FreshUntil:  freshUntil,
				},
			}
			if isStale {
				return NewStaleOutcome(p.Kind(), p.Name(), sigs, now, now, "upstream returned stale history cache")
			}
			return NewAvailableOutcome(p.Kind(), p.Name(), sigs, now, freshUntil)
		}
	}

	// Timeline parsing
	if doc.Time == nil {
		sigs := []verdict.Signal{
			{
				Kind:        KindPublishHistory,
				Source:      p.Name(),
				Observation: "missing_timeline",
				Confidence:  ConfidenceLow,
				RetrievedAt: now,
				FreshUntil:  freshUntil,
			},
		}
		return NewDegradedOutcome(p.Kind(), p.Name(), sigs, now, freshUntil, "packument is missing time metadata")
	}

	verTimeStr, hasVerTime := doc.Time[q.Version]
	createdTimeStr, hasCreatedTime := doc.Time["created"]

	if !hasVerTime || !hasCreatedTime {
		sigs := []verdict.Signal{
			{
				Kind:        KindPublishHistory,
				Source:      p.Name(),
				Observation: "missing_version_time",
				Confidence:  ConfidenceLow,
				RetrievedAt: now,
				FreshUntil:  freshUntil,
			},
		}
		return NewDegradedOutcome(p.Kind(), p.Name(), sigs, now, freshUntil, "packument time metadata missing version timestamp")
	}

	verTime, errVer := time.Parse(time.RFC3339Nano, verTimeStr)
	createdTime, errCreated := time.Parse(time.RFC3339Nano, createdTimeStr)
	if errVer != nil || errCreated != nil {
		sigs := []verdict.Signal{
			{
				Kind:        KindPublishHistory,
				Source:      p.Name(),
				Observation: "invalid_timestamp",
				Confidence:  ConfidenceLow,
				RetrievedAt: now,
				FreshUntil:  freshUntil,
			},
		}
		return NewDegradedOutcome(p.Kind(), p.Name(), sigs, now, freshUntil, "invalid timestamp format in time metadata")
	}

	// Future timestamp conflict check
	if verTime.After(now.Add(10 * time.Minute)) {
		sigs := []verdict.Signal{
			{
				Kind:        KindPublishHistory,
				Source:      p.Name(),
				Observation: "conflicting_future_timestamp",
				Confidence:  ConfidenceLow,
				RetrievedAt: now,
				FreshUntil:  freshUntil,
			},
		}
		return NewDegradedOutcome(p.Kind(), p.Name(), sigs, now, freshUntil, "version publish timestamp is in the future")
	}

	pkgAge := now.Sub(createdTime)
	versionAge := now.Sub(verTime)

	var signals []verdict.Signal

	// Package age / freshness signal
	if pkgAge < p.newbornThreshold {
		signals = append(signals, verdict.Signal{
			Kind:        KindPackageAge,
			Source:      p.Name(),
			Observation: "newborn",
			Confidence:  ConfidenceHigh,
			RetrievedAt: now,
			FreshUntil:  freshUntil,
		})
	} else if versionAge < p.freshThreshold {
		signals = append(signals, verdict.Signal{
			Kind:        KindPackageAge,
			Source:      p.Name(),
			Observation: "fresh",
			Confidence:  ConfidenceHigh,
			RetrievedAt: now,
			FreshUntil:  freshUntil,
		})
	} else {
		signals = append(signals, verdict.Signal{
			Kind:        KindPackageAge,
			Source:      p.Name(),
			Observation: "mature",
			Confidence:  ConfidenceHigh,
			RetrievedAt: now,
			FreshUntil:  freshUntil,
		})
	}

	// Dormant release revival check:
	// Find the release timestamp immediately preceding this version
	type versionEntry struct {
		version string
		time    time.Time
	}

	var timeline []versionEntry
	for v, tStr := range doc.Time {
		if v == "created" || v == "modified" {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, tStr)
		if err == nil {
			timeline = append(timeline, versionEntry{version: v, time: t})
		}
	}

	sort.Slice(timeline, func(i, j int) bool {
		return timeline[i].time.Before(timeline[j].time)
	})

	var prevEntry *versionEntry
	for i, entry := range timeline {
		if entry.version == q.Version {
			if i > 0 {
				prevEntry = &timeline[i-1]
			}
			break
		}
	}

	if prevEntry == nil {
		signals = append(signals, verdict.Signal{
			Kind:        KindPublishHistory,
			Source:      p.Name(),
			Observation: "initial_release",
			Confidence:  ConfidenceHigh,
			RetrievedAt: now,
			FreshUntil:  freshUntil,
		})
	} else {
		gap := verTime.Sub(prevEntry.time)
		if gap > p.dormantThreshold {
			signals = append(signals, verdict.Signal{
				Kind:        KindPublishHistory,
				Source:      p.Name(),
				Observation: "dormant_revival",
				Confidence:  ConfidenceHigh,
				RetrievedAt: now,
				FreshUntil:  freshUntil,
			})
		} else {
			signals = append(signals, verdict.Signal{
				Kind:        KindPublishHistory,
				Source:      p.Name(),
				Observation: "active_history",
				Confidence:  ConfidenceHigh,
				RetrievedAt: now,
				FreshUntil:  freshUntil,
			})
		}
	}

	if isStale {
		return NewStaleOutcome(p.Kind(), p.Name(), signals, now, now, "upstream returned stale history cache")
	}

	return NewAvailableOutcome(p.Kind(), p.Name(), signals, now, freshUntil)
}

func (p *HistoryProvider) now() time.Time {
	if p.clock != nil {
		return normalizeTime(p.clock())
	}
	return normalizeTime(time.Now())
}
