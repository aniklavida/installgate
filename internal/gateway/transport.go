package gateway

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aniklavida/installgate/internal/evidence"
	"github.com/aniklavida/installgate/internal/explanation"
	"github.com/aniklavida/installgate/internal/quarantine"
	"github.com/aniklavida/installgate/internal/verdict"
)

const (
	DefaultUpstreamURL  = "https://registry.npmjs.org"
	DefaultTimeout      = 30 * time.Second
	DefaultMaxBodyBytes = 100 * 1024 * 1024 // 100 MiB
)

var (
	errTimeout           = errors.New("gateway timeout: upstream request timed out")
	errConnectionFailed  = errors.New("bad gateway: upstream connection failed")
	errClientCancelled   = errors.New("bad gateway: client request cancelled")
	errBodyLimitExceeded = errors.New("bad gateway: response body exceeds size limit")
	errUnsupportedRoute  = errors.New("unsupported route: only public package metadata and tarball routes are supported")
)

var hopByHopHeaders = map[string]bool{
	"connection":          true,
	"proxy-connection":    true,
	"keep-alive":          true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"te":                  true,
	"trailer":             true,
	"transfer-encoding":   true,
	"upgrade":             true,
}

// Config configures the gateway transport and HTTP handler.
type Config struct {
	UpstreamBaseURL   string
	Transport         http.RoundTripper
	Timeout           time.Duration
	MaxBodyBytes      int64
	Evaluator         Evaluator
	DecisionStore     explanation.DecisionStore
	Quarantine        *quarantine.Manager
	IntegrityResolver quarantine.IntegrityResolver
}

// Evaluator assesses package requests against policy.
type Evaluator interface {
	Evaluate(ctx context.Context, pkg, version string) (*explanation.DecisionDocument, error)
}

// EvaluatorFunc adapts a function to the Evaluator interface.
type EvaluatorFunc func(ctx context.Context, pkg, version string) (*explanation.DecisionDocument, error)

func (f EvaluatorFunc) Evaluate(ctx context.Context, pkg, version string) (*explanation.DecisionDocument, error) {
	return f(ctx, pkg, version)
}

// UpstreamTransport performs round trips to the upstream npm registry
// for recognized metadata and tarball routes.
type UpstreamTransport struct {
	upstreamURL  *url.URL
	roundTripper http.RoundTripper
	timeout      time.Duration
	maxBodyBytes int64
}

// NewUpstreamTransport constructs an upstream transport with validated settings.
func NewUpstreamTransport(cfg Config) (*UpstreamTransport, error) {
	baseURLStr := cfg.UpstreamBaseURL
	if baseURLStr == "" {
		baseURLStr = DefaultUpstreamURL
	}
	parsed, err := url.Parse(baseURLStr)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("invalid upstream URL scheme: %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("invalid upstream URL host")
	}

	rt := cfg.Transport
	if rt == nil {
		rt = &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			DisableCompression:    true,
		}
	} else if t, ok := rt.(*http.Transport); ok {
		cloned := t.Clone()
		cloned.DisableCompression = true
		rt = cloned
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	maxBodyBytes := cfg.MaxBodyBytes
	if maxBodyBytes <= 0 {
		maxBodyBytes = DefaultMaxBodyBytes
	}

	return &UpstreamTransport{
		upstreamURL:  parsed,
		roundTripper: rt,
		timeout:      timeout,
		maxBodyBytes: maxBodyBytes,
	}, nil
}

// RoundTrip executes an upstream HTTP request for a classified read route.
func (t *UpstreamTransport) RoundTrip(ctx context.Context, route Route, clientReq *http.Request) (*http.Response, error) {
	if route.Kind != Metadata && route.Kind != Tarball {
		return nil, errUnsupportedRoute
	}

	targetURL, err := t.buildUpstreamURL(route, clientReq.URL.EscapedPath())
	if err != nil {
		return nil, err
	}
	if clientReq.URL.RawQuery != "" {
		targetURL.RawQuery = clientReq.URL.RawQuery
	}

	upstreamReq, err := http.NewRequestWithContext(ctx, clientReq.Method, targetURL.String(), nil)
	if err != nil {
		return nil, err
	}
	upstreamReq.Host = targetURL.Host
	upstreamReq.URL.RawPath = targetURL.RawPath

	copyClientHeaders(clientReq.Header, upstreamReq.Header)

	resp, err := t.roundTripper.RoundTrip(upstreamReq)
	if err != nil {
		return nil, sanitizeRoundTripError(err, ctx)
	}

	if t.maxBodyBytes > 0 && resp.ContentLength > t.maxBodyBytes {
		_ = resp.Body.Close()
		return nil, errBodyLimitExceeded
	}

	return resp, nil
}

func (t *UpstreamTransport) buildUpstreamURL(route Route, rawPath string) (*url.URL, error) {
	u := *t.upstreamURL
	basePrefix := strings.TrimSuffix(u.Path, "/")

	switch route.Kind {
	case Metadata:
		if strings.HasPrefix(route.Package, "@") {
			parts := strings.SplitN(route.Package, "/", 2)
			if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
				return nil, fmt.Errorf("invalid scoped package %q", route.Package)
			}
			u.Path = basePrefix + "/" + route.Package
			u.RawPath = basePrefix + "/" + parts[0] + "%2F" + parts[1]
		} else {
			u.Path = basePrefix + "/" + route.Package
			u.RawPath = ""
		}
		return &u, nil

	case Tarball:
		decoded, err := url.PathUnescape(rawPath)
		if err != nil {
			return nil, fmt.Errorf("invalid tarball path")
		}
		idx := strings.LastIndex(decoded, "/")
		if idx < 0 {
			return nil, fmt.Errorf("invalid tarball path")
		}
		filename := decoded[idx+1:]
		if !strings.HasSuffix(filename, ".tgz") {
			return nil, fmt.Errorf("invalid tarball filename")
		}
		u.Path = basePrefix + "/" + route.Package + "/-/" + filename
		u.RawPath = ""
		return &u, nil

	default:
		return nil, fmt.Errorf("unsupported route kind %q", route.Kind)
	}
}

// Handler handles incoming npm registry HTTP requests.
type Handler struct {
	transport         *UpstreamTransport
	timeout           time.Duration
	maxBodyBytes      int64
	evaluator         Evaluator
	decisionStore     explanation.DecisionStore
	quarantine        *quarantine.Manager
	integrityIndex    *quarantine.IntegrityIndex
	integrityResolver quarantine.IntegrityResolver
}

// NewHandler constructs a gateway Handler.
func NewHandler(cfg Config) (*Handler, error) {
	upstreamTransport, err := NewUpstreamTransport(cfg)
	if err != nil {
		return nil, err
	}

	integrityIndex := quarantine.NewIntegrityIndex()
	resolver := cfg.IntegrityResolver
	if resolver == nil {
		resolver = integrityIndex
	}

	return &Handler{
		transport:         upstreamTransport,
		timeout:           upstreamTransport.timeout,
		maxBodyBytes:      upstreamTransport.maxBodyBytes,
		evaluator:         cfg.Evaluator,
		decisionStore:     cfg.DecisionStore,
		quarantine:        cfg.Quarantine,
		integrityIndex:    integrityIndex,
		integrityResolver: resolver,
	}, nil
}

// Quarantine returns the quarantine manager configured on the handler, if any.
func (h *Handler) Quarantine() *quarantine.Manager {
	return h.quarantine
}

// IntegrityIndex returns the integrity registry on the handler.
func (h *Handler) IntegrityIndex() *quarantine.IntegrityIndex {
	return h.integrityIndex
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Header.Get("Authorization") != "" || req.Header.Get("Proxy-Authorization") != "" {
		http.Error(w, "unsupported request: authenticated and private registry flows are not supported", http.StatusBadRequest)
		return
	}

	route := Classify(req.Method, req.URL.EscapedPath())

	if route.Kind == Health {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if req.Method != http.MethodHead {
			_, _ = w.Write([]byte(`{"status":"ok"}` + "\n"))
		}
		return
	}

	if route.Kind == Unsupported {
		if req.Method != http.MethodGet && req.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, fmt.Sprintf("unsupported method %q: only GET and HEAD read requests are supported", req.Method), http.StatusMethodNotAllowed)
			return
		}
		http.Error(w, fmt.Sprintf("unsupported route %q: only public package metadata and tarball routes are supported", req.URL.EscapedPath()), http.StatusBadRequest)
		return
	}

	ctx := req.Context()
	if h.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, h.timeout)
		defer cancel()
	}

	// Route tarballs through quarantine when configured:
	// "QUARANTINE IS THE ONLY PATH by which InstallGate itself holds package bytes.
	// The gateway must not stream a tarball through to the client and inspect it afterwards."
	if route.Kind == Tarball && req.Method == http.MethodGet && h.quarantine != nil {
		h.handleQuarantinedTarball(w, req, route, ctx)
		return
	}

	if h.evaluator != nil && route.Package != "" {
		doc, err := h.evaluator.Evaluate(ctx, route.Package, route.Version)
		if err != nil {
			http.Error(w, "bad gateway: policy evaluation error", http.StatusBadGateway)
			return
		}
		if doc != nil && (doc.Verdict == verdict.Block || doc.Verdict == verdict.ApprovalRequired) {
			if h.decisionStore != nil {
				_ = h.decisionStore.Save(doc)
			}
			WriteBlockedResponse(w, doc)
			return
		}
	}

	resp, err := h.transport.RoundTrip(ctx, route, req)
	if err != nil {
		h.handleRoundTripError(w, err)
		return
	}
	defer resp.Body.Close()

	stopWatcher := context.AfterFunc(ctx, func() {
		_ = resp.Body.Close()
	})
	defer stopWatcher()

	if resp.StatusCode >= 500 {
		http.Error(w, "bad gateway: upstream service error", http.StatusBadGateway)
		return
	}

	copyResponseHeaders(resp.Header, w.Header())
	w.WriteHeader(resp.StatusCode)

	if req.Method == http.MethodHead || resp.StatusCode == http.StatusNotModified {
		return
	}

	var reader io.Reader = resp.Body
	if h.maxBodyBytes > 0 {
		reader = &limitedBodyReader{
			r:     resp.Body,
			limit: h.maxBodyBytes,
		}
	}

	// For metadata responses, snoop version integrities to populate the integrity index
	var metadataBuf bytes.Buffer
	if route.Kind == Metadata && resp.StatusCode == http.StatusOK && h.integrityIndex != nil {
		reader = io.TeeReader(reader, &metadataBuf)
	}

	_, err = io.Copy(w, reader)
	if err != nil {
		if errors.Is(err, errBodyLimitExceeded) {
			panic(http.ErrAbortHandler)
		}
		return
	}

	if route.Kind == Metadata && resp.StatusCode == http.StatusOK && h.integrityIndex != nil {
		h.indexPackumentIntegrities(route.Package, metadataBuf.Bytes())
	}
}

func (h *Handler) handleRoundTripError(w http.ResponseWriter, err error) {
	if errors.Is(err, errTimeout) {
		http.Error(w, err.Error(), http.StatusGatewayTimeout)
		return
	}
	if errors.Is(err, errBodyLimitExceeded) {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if errors.Is(err, errClientCancelled) {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	http.Error(w, "bad gateway: upstream connection failed", http.StatusBadGateway)
}

type limitedBodyReader struct {
	r     io.Reader
	limit int64
	read  int64
}

func (lr *limitedBodyReader) Read(p []byte) (int, error) {
	n, err := lr.r.Read(p)
	lr.read += int64(n)
	if lr.read > lr.limit {
		return n, errBodyLimitExceeded
	}
	return n, err
}

func copyClientHeaders(src, dst http.Header) {
	for k, vv := range src {
		if isHopByHop(k) {
			continue
		}
		if strings.EqualFold(k, "Authorization") ||
			strings.EqualFold(k, "Proxy-Authorization") ||
			strings.EqualFold(k, "Cookie") {
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func copyResponseHeaders(src, dst http.Header) {
	var connectionTokens []string
	if conn := src.Get("Connection"); conn != "" {
		for _, token := range strings.Split(conn, ",") {
			connectionTokens = append(connectionTokens, strings.TrimSpace(token))
		}
	}

	for k, vv := range src {
		if isConnectionHeader(k, connectionTokens) {
			continue
		}
		if strings.EqualFold(k, "Set-Cookie") {
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func isHopByHop(header string) bool {
	return hopByHopHeaders[strings.ToLower(header)]
}

func isConnectionHeader(header string, connectionTokens []string) bool {
	lower := strings.ToLower(header)
	if hopByHopHeaders[lower] {
		return true
	}
	for _, token := range connectionTokens {
		if strings.ToLower(token) == lower {
			return true
		}
	}
	return false
}

func sanitizeRoundTripError(err error, ctx context.Context) error {
	if errors.Is(err, context.DeadlineExceeded) || (ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded)) {
		return errTimeout
	}
	if errors.Is(err, context.Canceled) || (ctx != nil && errors.Is(ctx.Err(), context.Canceled)) {
		return errClientCancelled
	}
	return errConnectionFailed
}

// WriteBlockedResponse formats and writes a 403 Forbidden response surfacing the decision ID.
func WriteBlockedResponse(w http.ResponseWriter, doc *explanation.DecisionDocument) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-InstallGate-Decision", doc.DecisionID)
	w.Header().Set("X-InstallGate-Verdict", string(doc.Verdict))
	w.WriteHeader(http.StatusForbidden)

	errMsg := fmt.Sprintf("InstallGate: installation %s for %s@%s (decision: %s). Run 'installgate explain %s' to view reasons and next steps.",
		doc.Verdict, doc.Package, doc.Version, doc.DecisionID, doc.DecisionID)

	payload := map[string]string{
		"error":       errMsg,
		"decision_id": doc.DecisionID,
		"verdict":     string(doc.Verdict),
	}
	_ = json.NewEncoder(w).Encode(payload)
}

func (h *Handler) handleQuarantinedTarball(w http.ResponseWriter, req *http.Request, route Route, ctx context.Context) {
	// 1. Pre-fetch policy check
	if h.evaluator != nil && route.Package != "" {
		doc, err := h.evaluator.Evaluate(ctx, route.Package, route.Version)
		if err != nil {
			http.Error(w, "bad gateway: policy evaluation error", http.StatusBadGateway)
			return
		}
		if doc != nil && (doc.Verdict == verdict.Block || doc.Verdict == verdict.ApprovalRequired) {
			if h.decisionStore != nil {
				_ = h.decisionStore.Save(doc)
			}
			WriteBlockedResponse(w, doc)
			return
		}
	}

	// 2. Fetch tarball from upstream
	resp, err := h.transport.RoundTrip(ctx, route, req)
	if err != nil {
		h.handleRoundTripError(w, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 {
		http.Error(w, "bad gateway: upstream service error", http.StatusBadGateway)
		return
	}

	// For non-200 responses (e.g. 302 redirect, 304, 404), pass through upstream response
	if resp.StatusCode != http.StatusOK {
		copyResponseHeaders(resp.Header, w.Header())
		w.WriteHeader(resp.StatusCode)
		return
	}

	// 3. Resolve expected integrity digest
	expectedIntegrity, err := h.resolveExpectedIntegrity(ctx, route.Package, route.Version, req.Header.Get("X-Package-Integrity"))
	if err != nil || expectedIntegrity == "" {
		doc := h.makeIntegrityDecisionDoc(route.Package, route.Version, "unresolvable", "upstream package integrity could not be resolved")
		if h.decisionStore != nil {
			_ = h.decisionStore.Save(doc)
		}
		WriteBlockedResponse(w, doc)
		return
	}

	// 4. Ingest into quarantine: FIRST INTEGRITY VERIFICATION
	entry, err := h.quarantine.Ingest(ctx, route.Package, route.Version, expectedIntegrity, resp.Body)
	if err != nil {
		if errors.Is(err, quarantine.ErrIntegrityMismatch) {
			doc := h.makeIntegrityDecisionDoc(route.Package, route.Version, "mismatch", "package integrity verification failed (checksum mismatch)")
			if h.decisionStore != nil {
				_ = h.decisionStore.Save(doc)
			}
			WriteBlockedResponse(w, doc)
			return
		}
		http.Error(w, "bad gateway: quarantine ingestion failed", http.StatusBadGateway)
		return
	}

	// 5. Safe static inspection
	inspection, err := h.quarantine.Inspect(ctx, entry)
	if err != nil {
		doc := h.makeIntegrityDecisionDoc(route.Package, route.Version, "failed", fmt.Sprintf("quarantine inspection rejected unsafe archive structure: %v", err))
		if h.decisionStore != nil {
			_ = h.decisionStore.Save(doc)
		}
		WriteBlockedResponse(w, doc)
		return
	}

	if len(inspection.DangerousScripts) > 0 {
		doc := h.makeDangerousScriptDecisionDoc(route.Package, route.Version, inspection)
		if h.decisionStore != nil {
			_ = h.decisionStore.Save(doc)
		}
		WriteBlockedResponse(w, doc)
		return
	}

	if inspection.Truncated {
		doc := h.makeTruncatedInspectionDecisionDoc(route.Package, route.Version, inspection)
		if h.decisionStore != nil {
			_ = h.decisionStore.Save(doc)
		}
	}

	// 6. Post-inspection policy evaluation
	if h.evaluator != nil {
		doc, err := h.evaluator.Evaluate(ctx, route.Package, route.Version)
		if err != nil {
			http.Error(w, "bad gateway: policy evaluation error", http.StatusBadGateway)
			return
		}
		if doc != nil {
			if inspection.Truncated {
				doc.Degraded = true
			}
			if doc.Verdict == verdict.Block || doc.Verdict == verdict.ApprovalRequired {
				if h.decisionStore != nil {
					_ = h.decisionStore.Save(doc)
				}
				WriteBlockedResponse(w, doc)
				return
			}
		}
	}

	// 7. SECOND INTEGRITY VERIFICATION before release
	releaseStream, releaseSize, err := h.quarantine.VerifyAndRelease(ctx, entry.Key, expectedIntegrity)
	if err != nil {
		if errors.Is(err, quarantine.ErrIntegrityMismatchSecond) {
			doc := h.makeIntegrityDecisionDoc(route.Package, route.Version, "mismatch", "second integrity verification failed: blob modified or corrupted before release")
			if h.decisionStore != nil {
				_ = h.decisionStore.Save(doc)
			}
			WriteBlockedResponse(w, doc)
			return
		}
		http.Error(w, "bad gateway: quarantine release failed", http.StatusBadGateway)
		return
	}
	defer releaseStream.Close()

	// 8. Deliver verified blob to client
	copyResponseHeaders(resp.Header, w.Header())
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", releaseSize))
	w.WriteHeader(http.StatusOK)

	_, _ = io.Copy(w, releaseStream)
}

func (h *Handler) resolveExpectedIntegrity(ctx context.Context, pkg, version, headerIntegrity string) (string, error) {
	if headerIntegrity != "" {
		return headerIntegrity, nil
	}
	if h.integrityIndex != nil {
		if val, ok := h.integrityIndex.Get(pkg, version); ok {
			return val, nil
		}
	}
	if h.integrityResolver != nil {
		val, err := h.integrityResolver.ResolveIntegrity(ctx, pkg, version)
		if err == nil && val != "" {
			return val, nil
		}
	}

	metaRoute := Route{Kind: Metadata, Package: pkg}
	dummyReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://dummy/"+pkg, nil)
	if err != nil {
		return "", err
	}
	dummyReq.Header.Set("Accept", "application/json")

	resp, err := h.transport.RoundTrip(ctx, metaRoute, dummyReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("upstream returned status %d fetching metadata", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	h.indexPackumentIntegrities(pkg, bodyBytes)

	if h.integrityIndex != nil {
		if val, ok := h.integrityIndex.Get(pkg, version); ok {
			return val, nil
		}
	}

	return "", fmt.Errorf("integrity not found for %s@%s", pkg, version)
}

func (h *Handler) indexPackumentIntegrities(pkg string, data []byte) {
	if len(data) == 0 {
		return
	}
	var reader io.Reader = bytes.NewReader(data)
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		gz, err := gzip.NewReader(reader)
		if err == nil {
			defer gz.Close()
			reader = gz
		}
	}

	var doc struct {
		Versions map[string]struct {
			Dist struct {
				Integrity string `json:"integrity"`
				Shasum    string `json:"shasum"`
			} `json:"dist"`
		} `json:"versions"`
	}

	if err := json.NewDecoder(reader).Decode(&doc); err == nil {
		for ver, verDoc := range doc.Versions {
			integ := verDoc.Dist.Integrity
			if integ == "" {
				integ = verDoc.Dist.Shasum
			}
			if integ != "" && h.integrityIndex != nil {
				h.integrityIndex.Set(pkg, ver, integ)
			}
		}
	}
}

func (h *Handler) makeIntegrityDecisionDoc(pkg, version, observation, summary string) *explanation.DecisionDocument {
	now := time.Now().UTC().Truncate(time.Millisecond)
	sig := verdict.Signal{
		Kind:        evidence.KindIntegrity,
		Source:      "quarantine",
		Observation: observation,
		Confidence:  evidence.ConfidenceHigh,
		RetrievedAt: now,
		FreshUntil:  now.Add(24 * time.Hour),
	}
	states := map[string]evidence.State{
		evidence.KindIntegrity: evidence.StateAvailable,
	}
	snap := evidence.NewSnapshot(pkg, version, []verdict.Signal{sig}, states, now)
	dec := verdict.Decision{
		Verdict: verdict.Block,
		Reasons: []verdict.Reason{{
			RuleID:      "core.integrity-or-malicious",
			Summary:     summary,
			SignalKinds: []string{evidence.KindIntegrity},
		}},
	}
	doc, _ := explanation.NewDecisionDocument(pkg, version, dec, snap, explanation.WithReferenceTime(now))
	return doc
}

func (h *Handler) makeDangerousScriptDecisionDoc(pkg, version string, inspection *quarantine.ArchiveInspection) *explanation.DecisionDocument {
	now := time.Now().UTC().Truncate(time.Millisecond)
	scriptNames := inspection.DangerousScripts
	scriptName := strings.Join(scriptNames, ", ")
	summary := fmt.Sprintf("dangerous install script detected in %s", scriptName)
	if len(inspection.DangerousReasons) > 0 {
		summary = fmt.Sprintf("dangerous install script detected in %s: %s", scriptName, strings.Join(inspection.DangerousReasons, "; "))
	}

	signals := inspection.Signals
	if len(signals) == 0 {
		signals = append(signals, verdict.Signal{
			Kind:        evidence.KindInstallScript,
			Source:      "quarantine_inspect",
			Observation: fmt.Sprintf("dangerous_script:%s", scriptName),
			Confidence:  evidence.ConfidenceHigh,
			RetrievedAt: now,
			FreshUntil:  now.Add(24 * time.Hour),
		})
	}

	state := evidence.StateAvailable
	if inspection.Truncated {
		state = evidence.StateDegraded
	}
	states := map[string]evidence.State{
		evidence.KindInstallScript: state,
	}
	snap := evidence.NewSnapshot(pkg, version, signals, states, now)
	dec := verdict.Decision{
		Verdict: verdict.Block,
		Reasons: []verdict.Reason{{
			RuleID:      "execution.dangerous-install-script",
			Summary:     summary,
			SignalKinds: []string{evidence.KindInstallScript},
		}},
		Degraded: inspection.Truncated,
	}
	doc, _ := explanation.NewDecisionDocument(pkg, version, dec, snap, explanation.WithReferenceTime(now))
	return doc
}

func (h *Handler) makeTruncatedInspectionDecisionDoc(pkg, version string, inspection *quarantine.ArchiveInspection) *explanation.DecisionDocument {
	now := time.Now().UTC().Truncate(time.Millisecond)
	signals := inspection.Signals
	states := map[string]evidence.State{
		evidence.KindInstallScript: evidence.StateDegraded,
	}
	snap := evidence.NewSnapshot(pkg, version, signals, states, now)
	dec := verdict.Decision{
		Verdict: verdict.Warn,
		Reasons: []verdict.Reason{{
			RuleID:      "execution.install-time",
			Summary:     "inspection limits were reached; analysis degraded",
			SignalKinds: []string{evidence.KindInstallScript},
		}},
		Degraded: true,
	}
	doc, _ := explanation.NewDecisionDocument(pkg, version, dec, snap, explanation.WithReferenceTime(now))
	return doc
}
