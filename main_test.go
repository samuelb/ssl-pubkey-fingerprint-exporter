package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func TestParseTarget(t *testing.T) {
	var tests = []struct {
		name        string
		input       string
		output      string
		shouldError bool
	}{
		{"default HTTPS port", "https://example.com", "example.com:443", false},
		{"case insensitive scheme", "HTTPS://example.com", "example.com:443", false},
		{"default LDAPS port", "ldaps://example.com", "example.com:636", false},
		{"explicit URL port", "https://example.com:1234", "example.com:1234", false},
		{"host and port", "example.com:1234", "example.com:1234", false},
		{"IPv6 URL", "https://[::1]", "[::1]:443", false},
		{"IPv6 and port", "[::1]:1234", "[::1]:1234", false},
		{"empty target", "", "", true},
		{"missing port", "example.com", "", true},
		{"missing scheme", "//example.com", "", true},
		{"unknown scheme", "foobar://example.com", "", true},
		{"empty host", ":443", "", true},
		{"URL with empty host", "https://:443", "", true},
		{"empty port", "https://example.com:", "", true},
		{"schemeless empty port", "example.com:", "", true},
		{"zero port", "example.com:0", "", true},
		{"port too large", "example.com:65536", "", true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := parseTarget(test.input)
			if res != test.output {
				t.Errorf("input %q: got %q, should be %q", test.input, res, test.output)
			}
			if test.shouldError && err == nil {
				t.Errorf("input %q didn't error, but it should", test.input)
			}
			if !test.shouldError && err != nil {
				t.Errorf("input %q errored unexpectedly: %v", test.input, err)
			}
		})
	}
}

func TestGetScrapeTimeout(t *testing.T) {
	defaultTimeout := 10 * time.Second

	var tests = []struct {
		name        string
		header      string
		output      time.Duration
		shouldError bool
	}{
		{"no header", "", defaultTimeout, false},
		{"header with offset headroom", "5", 4500 * time.Millisecond, false},
		{"header below offset", "0.2", 100 * time.Millisecond, false},
		{"negative header", "-1", 0, true},
		{"zero header", "0", 0, true},
		{"NaN header", "NaN", 0, true},
		{"infinite header", "+Inf", 0, true},
		{"overflowing header", "1e20", 0, true},
		{"duration boundary header", "9223372037.354776", 0, true},
		{"sub-nanosecond header", "1e-10", 0, true},
		{"invalid header", "not-a-number", 0, true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/probe", nil)
			if test.header != "" {
				r.Header.Set("X-Prometheus-Scrape-Timeout-Seconds", test.header)
			}

			timeout, err := getScrapeTimeout(r, defaultTimeout)
			if test.shouldError {
				if err == nil {
					t.Errorf("header %q didn't error, but it should", test.header)
				}
				return
			}
			if err != nil {
				t.Fatalf("header %q errored unexpectedly: %v", test.header, err)
			}
			if timeout != test.output {
				t.Errorf("header %q: got %v, should be %v", test.header, timeout, test.output)
			}
		})
	}
}

func TestGetConfig(t *testing.T) {
	tests := []struct {
		name           string
		listenAddress  string
		defaultTimeout string
		maxConcurrent  string
		logLevel       string
		logFormat      string
		want           Config
		shouldError    bool
	}{
		{
			name: "defaults",
			want: Config{
				ListenAddress:       defaultListenAddress,
				DefaultTimeout:      defaultTimeout,
				MaxConcurrentProbes: defaultMaxConcurrent,
				LogLevel:            slog.LevelInfo,
				LogFormat:           defaultLogFormat,
			},
		},
		{
			name:           "integer seconds",
			listenAddress:  ":8080",
			defaultTimeout: "15",
			maxConcurrent:  "8",
			want: Config{
				ListenAddress:       ":8080",
				DefaultTimeout:      15 * time.Second,
				MaxConcurrentProbes: 8,
				LogLevel:            slog.LevelInfo,
				LogFormat:           defaultLogFormat,
			},
		},
		{
			name:           "duration",
			defaultTimeout: "750ms",
			want: Config{
				ListenAddress:       defaultListenAddress,
				DefaultTimeout:      750 * time.Millisecond,
				MaxConcurrentProbes: defaultMaxConcurrent,
				LogLevel:            slog.LevelInfo,
				LogFormat:           defaultLogFormat,
			},
		},
		{
			name:      "log level and format",
			logLevel:  "debug",
			logFormat: "JSON",
			want: Config{
				ListenAddress:       defaultListenAddress,
				DefaultTimeout:      defaultTimeout,
				MaxConcurrentProbes: defaultMaxConcurrent,
				LogLevel:            slog.LevelDebug,
				LogFormat:           "json",
			},
		},
		{name: "invalid timeout", defaultTimeout: "later", shouldError: true},
		{name: "zero timeout", defaultTimeout: "0", shouldError: true},
		{name: "negative timeout", defaultTimeout: "-1s", shouldError: true},
		{name: "overflowing seconds", defaultTimeout: "999999999999999999", shouldError: true},
		{name: "integer parse overflow", defaultTimeout: "99999999999999999999999", shouldError: true},
		{name: "invalid concurrency", maxConcurrent: "many", shouldError: true},
		{name: "zero concurrency", maxConcurrent: "0", shouldError: true},
		{name: "invalid log level", logLevel: "verbose", shouldError: true},
		{name: "invalid log format", logFormat: "logfmt", shouldError: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("LISTEN_ADDRESS", test.listenAddress)
			t.Setenv("DEFAULT_TIMEOUT", test.defaultTimeout)
			t.Setenv("MAX_CONCURRENT_PROBES", test.maxConcurrent)
			t.Setenv("LOG_LEVEL", test.logLevel)
			t.Setenv("LOG_FORMAT", test.logFormat)

			config, err := getConfig()
			if test.shouldError {
				if err == nil {
					t.Fatal("getConfig did not return an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("getConfig returned an unexpected error: %v", err)
			}
			if config != test.want {
				t.Errorf("getConfig returned %+v, want %+v", config, test.want)
			}
		})
	}
}

// expectedFingerprint computes the base64-encoded SHA-256 hash of the
// DER-encoded public key of the given TLS test server's certificate.
func expectedFingerprint(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(ts.Certificate().PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal test server public key: %v", err)
	}
	hash := sha256.Sum256(der)
	return base64.StdEncoding.EncodeToString(hash[:])
}

func TestGetFingerprint(t *testing.T) {
	ts := httptest.NewTLSServer(http.NotFoundHandler())
	defer ts.Close()

	fingerprint, err := getFingerprint(context.Background(), ts.Listener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("getFingerprint errored unexpectedly: %v", err)
	}

	if want := expectedFingerprint(t, ts); fingerprint != want {
		t.Errorf("got fingerprint %q, should be %q", fingerprint, want)
	}
}

func TestGetFingerprintNonTLSTarget(t *testing.T) {
	ts := httptest.NewServer(http.NotFoundHandler())
	defer ts.Close()

	if _, err := getFingerprint(context.Background(), ts.Listener.Addr().String(), 5*time.Second); err == nil {
		t.Error("getFingerprint didn't error on a non-TLS target, but it should")
	}
}

func TestProbeHandler(t *testing.T) {
	ts := httptest.NewTLSServer(http.NotFoundHandler())
	defer ts.Close()

	metricsRegistry := prometheus.NewRegistry()
	handler := probeHandler(
		Config{DefaultTimeout: 5 * time.Second, MaxConcurrentProbes: 2},
		newProbeMetrics(metricsRegistry),
	)

	t.Run("missing target", func(t *testing.T) {
		w := httptest.NewRecorder()
		handler(w, httptest.NewRequest(http.MethodGet, "/probe", nil))
		if w.Code != http.StatusBadRequest {
			t.Errorf("got status %d, should be %d", w.Code, http.StatusBadRequest)
		}
	})

	t.Run("successful probe", func(t *testing.T) {
		w := httptest.NewRecorder()
		handler(w, httptest.NewRequest(http.MethodGet, "/probe?target="+ts.Listener.Addr().String(), nil))
		if w.Code != http.StatusOK {
			t.Fatalf("got status %d, should be %d", w.Code, http.StatusOK)
		}
		body := w.Body.String()
		if !strings.Contains(body, "# TYPE spki_fingerprint gauge") {
			t.Errorf("body should contain the SPKI fingerprint metric, got:\n%s", body)
		}
		if !strings.Contains(body, "probe_success 1") {
			t.Errorf("body should contain probe_success 1, got:\n%s", body)
		}
		if !strings.Contains(body, `fingerprint="`+expectedFingerprint(t, ts)+`"`) {
			t.Errorf("body should contain the expected fingerprint, got:\n%s", body)
		}
	})

	t.Run("failed probe", func(t *testing.T) {
		// Reserve a port and close the listener so the probe is refused.
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to create listener: %v", err)
		}
		addr := l.Addr().String()
		l.Close()

		w := httptest.NewRecorder()
		handler(w, httptest.NewRequest(http.MethodGet, "/probe?target="+addr, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("got status %d, should be %d", w.Code, http.StatusOK)
		}
		if body := w.Body.String(); !strings.Contains(body, "probe_success 0") {
			t.Errorf("body should contain probe_success 0, got:\n%s", body)
		}
	})
}

func TestProbeHandlerConcurrencyLimit(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()

	metricsRegistry := prometheus.NewRegistry()
	handler := probeHandler(
		Config{DefaultTimeout: 5 * time.Second, MaxConcurrentProbes: 1},
		newProbeMetrics(metricsRegistry),
	)

	ctx, cancel := context.WithCancel(context.Background())
	firstDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/probe?target="+listener.Addr().String(), nil).WithContext(ctx)
		handler(w, r)
		firstDone <- w
	}()

	var conn net.Conn
	select {
	case conn = <-accepted:
		defer conn.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("first probe did not connect")
	}

	second := httptest.NewRecorder()
	handler(second, httptest.NewRequest(http.MethodGet, "/probe?target="+listener.Addr().String(), nil))
	if second.Code != http.StatusServiceUnavailable {
		t.Errorf("second probe returned status %d, want %d", second.Code, http.StatusServiceUnavailable)
	}
	if retryAfter := second.Header().Get("Retry-After"); retryAfter != "1" {
		t.Errorf("second probe returned Retry-After %q, want %q", retryAfter, "1")
	}

	cancel()
	select {
	case first := <-firstDone:
		if first.Code != http.StatusOK {
			t.Errorf("cancelled first probe returned status %d, want %d", first.Code, http.StatusOK)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first probe did not stop after cancellation")
	}

	metricsResponse := httptest.NewRecorder()
	promhttp.HandlerFor(metricsRegistry, promhttp.HandlerOpts{}).ServeHTTP(
		metricsResponse,
		httptest.NewRequest(http.MethodGet, "/metrics", nil),
	)
	metricsBody := metricsResponse.Body.String()
	if !strings.Contains(metricsBody, "spki_fingerprint_exporter_rejected_probes_total 1") {
		t.Errorf("metrics should contain one rejected probe, got:\n%s", metricsBody)
	}
	if !strings.Contains(metricsBody, `spki_fingerprint_exporter_probes_total{result="failure"} 1`) {
		t.Errorf("metrics should contain one failed probe, got:\n%s", metricsBody)
	}
	if !strings.Contains(metricsBody, "spki_fingerprint_exporter_active_probes 0") {
		t.Errorf("metrics should contain zero active probes, got:\n%s", metricsBody)
	}
}

func TestHTTPRoutes(t *testing.T) {
	registry := prometheus.NewRegistry()
	handler := newHandler(
		Config{DefaultTimeout: time.Second, MaxConcurrentProbes: 1},
		registry,
		registry,
	)

	tests := []struct {
		name        string
		method      string
		path        string
		status      int
		contentType string
	}{
		{"root", http.MethodGet, "/", http.StatusOK, "text/html; charset=utf-8"},
		{"healthy", http.MethodGet, "/-/healthy", http.StatusOK, "text/plain; charset=utf-8"},
		{"healthy head", http.MethodHead, "/-/healthy", http.StatusOK, "text/plain; charset=utf-8"},
		{"ready", http.MethodGet, "/-/ready", http.StatusOK, "text/plain; charset=utf-8"},
		{"unknown", http.MethodGet, "/unknown", http.StatusNotFound, "text/plain; charset=utf-8"},
		{"root method", http.MethodPost, "/", http.StatusMethodNotAllowed, "text/plain; charset=utf-8"},
		{"probe method", http.MethodPost, "/probe", http.StatusMethodNotAllowed, "text/plain; charset=utf-8"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest(test.method, test.path, nil))
			if w.Code != test.status {
				t.Errorf("status = %d, want %d", w.Code, test.status)
			}
			if contentType := w.Header().Get("Content-Type"); contentType != test.contentType {
				t.Errorf("Content-Type = %q, want %q", contentType, test.contentType)
			}
		})
	}
}

func TestBuildInfoMetric(t *testing.T) {
	registry := prometheus.NewRegistry()
	handler := newHandler(
		Config{DefaultTimeout: time.Second, MaxConcurrentProbes: 1},
		registry,
		registry,
	)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(w.Body.String(), `spki_fingerprint_exporter_build_info{`) {
		t.Errorf("metrics should contain build_info, got:\n%s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `version="dev"`) {
		t.Errorf("build_info should carry the version label, got:\n%s", w.Body.String())
	}
}

func TestRootEscapesVersion(t *testing.T) {
	originalVersion := Version
	Version = `<script>alert("version")</script>`
	t.Cleanup(func() { Version = originalVersion })

	registry := prometheus.NewRegistry()
	handler := newHandler(
		Config{DefaultTimeout: time.Second, MaxConcurrentProbes: 1},
		registry,
		registry,
	)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if !strings.Contains(w.Body.String(), "<title>SPKI fingerprint exporter</title>") {
		t.Errorf("root page does not contain the renamed project title: %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "<script>") {
		t.Errorf("root page contains unescaped version: %s", w.Body.String())
	}
}

func TestServeGracefulShutdown(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	server := newServer(Config{}, http.NewServeMux())
	go func() {
		done <- serve(ctx, server, listener)
	}()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve returned an error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not shut down after cancellation")
	}
}
