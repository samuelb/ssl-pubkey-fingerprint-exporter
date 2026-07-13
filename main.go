package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// Version is set during build
	Version = "dev"

	spkiFingerprint = prometheus.NewDesc(
		"spki_fingerprint",
		"TLS certificate Subject Public Key Info (SPKI) SHA-256 fingerprint.",
		[]string{"fingerprint", "target"}, nil,
	)

	probeSuccess = prometheus.NewDesc(
		"probe_success",
		"Displays whether or not the probe was a success",
		nil, nil,
	)

	probeDuration = prometheus.NewDesc(
		"probe_duration_seconds",
		"Returns how long the probe took to complete in seconds",
		nil, nil,
	)

	// Default configuration
	defaultListenAddress = ":3000"
	defaultTimeout       = 10 * time.Second
	defaultMaxConcurrent = 64
	scrapeTimeoutOffset  = 500 * time.Millisecond

	// schemePorts maps URL schemes to their default ports. A static map is
	// used instead of net.LookupPort because the latter depends on
	// /etc/services, which does not exist in minimal container images.
	schemePorts = map[string]string{
		"https":       "443",
		"smtps":       "465",
		"submissions": "465",
		"nntps":       "563",
		"ldaps":       "636",
		"domain-s":    "853",
		"ftps":        "990",
		"imaps":       "993",
		"pop3s":       "995",
		"sips":        "5061",
	}
)

type Config struct {
	ListenAddress       string
	DefaultTimeout      time.Duration
	MaxConcurrentProbes int
}

type Exporter struct {
	ctx          context.Context
	target       string
	timeout      time.Duration
	once         sync.Once
	success      bool
	fingerprint  string
	parsedTarget string
	duration     time.Duration
}

type probeMetrics struct {
	active   prometheus.Gauge
	total    *prometheus.CounterVec
	rejected prometheus.Counter
}

func newProbeMetrics(registerer prometheus.Registerer) *probeMetrics {
	metrics := &probeMetrics{
		active: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "spki_fingerprint_exporter",
			Name:      "active_probes",
			Help:      "Number of TLS probes currently being handled.",
		}),
		total: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "spki_fingerprint_exporter",
			Name:      "probes_total",
			Help:      "Total number of completed TLS probes.",
		}, []string{"result"}),
		rejected: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "spki_fingerprint_exporter",
			Name:      "rejected_probes_total",
			Help:      "Total number of probes rejected because the concurrency limit was reached.",
		}),
	}
	registerer.MustRegister(metrics.active, metrics.total, metrics.rejected)
	metrics.total.WithLabelValues("success")
	metrics.total.WithLabelValues("failure")
	return metrics
}

func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- spkiFingerprint
	ch <- probeSuccess
	ch <- probeDuration
}

func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	e.once.Do(e.runProbe)
	if e.success {
		ch <- prometheus.MustNewConstMetric(
			spkiFingerprint, prometheus.GaugeValue, 1, e.fingerprint, e.parsedTarget,
		)
	}
	ch <- prometheus.MustNewConstMetric(
		probeDuration, prometheus.GaugeValue, e.duration.Seconds(),
	)

	successValue := 0.0
	if e.success {
		successValue = 1
	}
	ch <- prometheus.MustNewConstMetric(
		probeSuccess, prometheus.GaugeValue, successValue,
	)
}

func (e *Exporter) runProbe() {
	start := time.Now()
	defer func() {
		e.duration = time.Since(start)
	}()

	target, err := parseTarget(e.target)
	if err != nil {
		slog.Error("Failed to parse target", "target", e.target, "error", err)
		return
	}

	fingerprint, err := getFingerprint(e.ctx, target, e.timeout)
	if err != nil {
		slog.Error("Failed to get SPKI fingerprint", "target", target, "error", err)
		return
	}

	e.success = true
	e.fingerprint = fingerprint
	e.parsedTarget = target
}

func getFingerprint(ctx context.Context, target string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{},
		// Certificate chain validation is intentionally skipped: this
		// exporter fingerprints the presented SPKI, it does not
		// validate the certificate.
		Config: &tls.Config{InsecureSkipVerify: true}, // #nosec G402
	}

	netConn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return "", fmt.Errorf("failed to establish TLS connection: %w", err)
	}
	defer netConn.Close()

	conn := netConn.(*tls.Conn)
	connstate := conn.ConnectionState()
	if len(connstate.PeerCertificates) == 0 {
		return "", errors.New("no peer certificates found")
	}

	leafcert := connstate.PeerCertificates[0]
	der, err := x509.MarshalPKIXPublicKey(leafcert.PublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	hash := sha256.Sum256(der)
	return base64.StdEncoding.EncodeToString(hash[:]), nil
}

func parseTarget(target string) (parsedTarget string, err error) {
	if !strings.Contains(target, "://") {
		target = "//" + target
	}

	u, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("failed to parse URL: %w", err)
	}

	host := u.Hostname()
	if host == "" {
		return "", errors.New("hostname is required")
	}

	port := u.Port()
	if port == "" {
		if strings.HasSuffix(u.Host, ":") {
			return "", errors.New("port number is empty")
		}
		if u.Scheme == "" {
			return "", errors.New("protocol scheme or port number is required")
		}
		p, ok := schemePorts[strings.ToLower(u.Scheme)]
		if !ok {
			return "", fmt.Errorf("unknown default port for scheme %s, specify the port explicitly", u.Scheme)
		}
		port = p
	}

	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", fmt.Errorf("invalid port number %q", port)
	}

	return net.JoinHostPort(host, port), nil
}

func probeHandler(config Config, metrics *probeMetrics) http.HandlerFunc {
	maxConcurrent := config.MaxConcurrentProbes
	if maxConcurrent <= 0 {
		maxConcurrent = defaultMaxConcurrent
	}
	probeSlots := make(chan struct{}, maxConcurrent)

	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		target := r.URL.Query().Get("target")
		if target == "" {
			http.Error(w, "target parameter is required", http.StatusBadRequest)
			return
		}

		timeout, err := getScrapeTimeout(r, config.DefaultTimeout)
		if err != nil {
			slog.Error("Failed to get scrape timeout", "error", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		select {
		case probeSlots <- struct{}{}:
			if metrics != nil {
				metrics.active.Inc()
			}
		default:
			if metrics != nil {
				metrics.rejected.Inc()
			}
			w.Header().Set("Retry-After", "1")
			http.Error(w, "maximum concurrent probes reached", http.StatusServiceUnavailable)
			return
		}

		exporter := &Exporter{
			ctx:     r.Context(),
			target:  target,
			timeout: timeout,
		}
		func() {
			defer func() {
				<-probeSlots
				if metrics != nil {
					metrics.active.Dec()
				}
			}()

			exporter.once.Do(exporter.runProbe)
			if metrics != nil {
				result := "failure"
				if exporter.success {
					result = "success"
				}
				metrics.total.WithLabelValues(result).Inc()
			}
		}()

		registry := prometheus.NewRegistry()
		registry.MustRegister(exporter)

		h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
		h.ServeHTTP(w, r)
	}
}

func getScrapeTimeout(r *http.Request, defaultTimeout time.Duration) (time.Duration, error) {
	if v := r.Header.Get("X-Prometheus-Scrape-Timeout-Seconds"); v != "" {
		timeoutSeconds, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return 0, fmt.Errorf("failed to parse timeout from Prometheus header: %w", err)
		}
		if math.IsNaN(timeoutSeconds) || math.IsInf(timeoutSeconds, 0) || timeoutSeconds <= 0 {
			return 0, fmt.Errorf("Prometheus scrape timeout must be a positive finite number, got %q", v)
		}
		// Leave some headroom to respond before Prometheus closes the
		// connection, like the blackbox exporter does. For timeouts
		// shorter than twice the offset, reserve half the timeout so
		// there is always room to report probe_success 0.
		timeoutSeconds = math.Max(timeoutSeconds-scrapeTimeoutOffset.Seconds(), timeoutSeconds/2)
		if timeoutSeconds >= float64(math.MaxInt64)/float64(time.Second) {
			return 0, fmt.Errorf("Prometheus scrape timeout is too large: %q", v)
		}
		timeout := time.Duration(timeoutSeconds * float64(time.Second))
		if timeout <= 0 {
			return 0, fmt.Errorf("Prometheus scrape timeout is too small: %q", v)
		}
		return timeout, nil
	}
	return defaultTimeout, nil
}

func getConfig() (Config, error) {
	config := Config{
		ListenAddress:       defaultListenAddress,
		DefaultTimeout:      defaultTimeout,
		MaxConcurrentProbes: defaultMaxConcurrent,
	}

	if addr := os.Getenv("LISTEN_ADDRESS"); addr != "" {
		config.ListenAddress = addr
	}

	if timeout := os.Getenv("DEFAULT_TIMEOUT"); timeout != "" {
		parsedTimeout, err := parseDefaultTimeout(timeout)
		if err != nil {
			return Config{}, err
		}
		config.DefaultTimeout = parsedTimeout
	}

	if value := os.Getenv("MAX_CONCURRENT_PROBES"); value != "" {
		maxConcurrent, err := strconv.Atoi(value)
		if err != nil || maxConcurrent <= 0 {
			return Config{}, fmt.Errorf("MAX_CONCURRENT_PROBES must be a positive integer, got %q", value)
		}
		config.MaxConcurrentProbes = maxConcurrent
	}

	return config, nil
}

func parseDefaultTimeout(value string) (time.Duration, error) {
	seconds, err := strconv.ParseInt(value, 10, 64)
	if err == nil {
		if seconds <= 0 || seconds > int64(math.MaxInt64)/int64(time.Second) {
			return 0, fmt.Errorf("DEFAULT_TIMEOUT must be positive and fit in a duration, got %q", value)
		}
		return time.Duration(seconds) * time.Second, nil
	}
	if errors.Is(err, strconv.ErrRange) {
		return 0, fmt.Errorf("DEFAULT_TIMEOUT integer seconds value is out of range: %q", value)
	}

	timeout, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("failed to parse DEFAULT_TIMEOUT %q: use seconds or a Go duration: %w", value, err)
	}
	if timeout <= 0 {
		return 0, fmt.Errorf("DEFAULT_TIMEOUT must be positive, got %q", value)
	}
	return timeout, nil
}

func newHandler(config Config, registerer prometheus.Registerer, gatherer prometheus.Gatherer) http.Handler {
	mux := http.NewServeMux()
	metricsHandler := promhttp.HandlerFor(gatherer, promhttp.HandlerOpts{})
	mux.Handle("/metrics", promhttp.InstrumentMetricHandler(registerer, metricsHandler))
	mux.HandleFunc("/probe", probeHandler(config, newProbeMetrics(registerer)))
	mux.HandleFunc("/-/healthy", healthHandler)
	mux.HandleFunc("/-/ready", healthHandler)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(fmt.Sprintf(`<html>
			<head><title>SPKI fingerprint exporter</title></head>
			<body>
			<h1>SPKI fingerprint exporter</h1>
			<p>Version: %s</p>
			<p><a href="/probe?target=example.com:443">Probe example.com:443 for TLS certificate SPKI fingerprint metrics</a></p>
			<p><a href='/metrics'>Metrics</a></p>
			</body>
			</html>`, html.EscapeString(Version))))
	})
	return mux
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("OK\n"))
}

func newServer(config Config, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              config.ListenAddress,
		Handler:           handler,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
}

func serve(ctx context.Context, server *http.Server, listener net.Listener) error {
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(listener)
	}()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		slog.Info("Shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("graceful shutdown failed: %w", err)
		}
		err := <-errCh
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

func run(ctx context.Context, config Config) error {
	listener, err := net.Listen("tcp", config.ListenAddress)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", config.ListenAddress, err)
	}
	handler := newHandler(config, prometheus.DefaultRegisterer, prometheus.DefaultGatherer)
	return serve(ctx, newServer(config, handler), listener)
}

func main() {
	config, err := getConfig()
	if err != nil {
		slog.Error("Invalid configuration", "error", err)
		os.Exit(1)
	}

	slog.Info("Starting server", "version", Version, "address", config.ListenAddress)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, config); err != nil {
		slog.Error("Server failed", "error", err)
		os.Exit(1)
	}
}
