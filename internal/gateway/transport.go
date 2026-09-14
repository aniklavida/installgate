package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
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
	UpstreamBaseURL string
	Transport       http.RoundTripper
	Timeout         time.Duration
	MaxBodyBytes    int64
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
	transport    *UpstreamTransport
	timeout      time.Duration
	maxBodyBytes int64
}

// NewHandler constructs a gateway Handler.
func NewHandler(cfg Config) (*Handler, error) {
	upstreamTransport, err := NewUpstreamTransport(cfg)
	if err != nil {
		return nil, err
	}
	return &Handler{
		transport:    upstreamTransport,
		timeout:      upstreamTransport.timeout,
		maxBodyBytes: upstreamTransport.maxBodyBytes,
	}, nil
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

	_, err = io.Copy(w, reader)
	if err != nil {
		if errors.Is(err, errBodyLimitExceeded) {
			panic(http.ErrAbortHandler)
		}
		return
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
