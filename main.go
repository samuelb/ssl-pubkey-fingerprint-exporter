package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// Version is set during build
	Version = "dev"

	pubkeyFingerprint = prometheus.NewDesc(
		"ssl_pubkey_fingerprint",
		"SSL certificate publickey SHA-256 fingerprint",
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
	ListenAddress  string
	DefaultTimeout time.Duration
}

type Exporter struct {
	ctx     context.Context
	target  string
	timeout time.Duration
}

func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- pubkeyFingerprint
	ch <- probeSuccess
	ch <- probeDuration
}

func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	start := time.Now()
	success := e.probe(ch)
	ch <- prometheus.MustNewConstMetric(
		probeDuration, prometheus.GaugeValue, time.Since(start).Seconds(),
	)

	successValue := 0.0
	if success {
		successValue = 1
	}
	ch <- prometheus.MustNewConstMetric(
		probeSuccess, prometheus.GaugeValue, successValue,
	)
}

func (e *Exporter) probe(ch chan<- prometheus.Metric) bool {
	target, err := parseTarget(e.target)
	if err != nil {
		slog.Error("Failed to parse target", "target", e.target, "error", err)
		return false
	}

	fingerprint, err := getFingerprint(e.ctx, target, e.timeout)
	if err != nil {
		slog.Error("Failed to get publickey fingerprint", "target", target, "error", err)
		return false
	}

	ch <- prometheus.MustNewConstMetric(
		pubkeyFingerprint, prometheus.GaugeValue, 1, fingerprint, target,
	)
	return true
}

func getFingerprint(ctx context.Context, target string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{},
		// Certificate chain validation is intentionally skipped: this
		// exporter fingerprints the presented public key, it does not
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

	port := u.Port()
	if port == "" {
		if u.Scheme == "" {
			return "", errors.New("protocol scheme or port number is required")
		}
		p, ok := schemePorts[u.Scheme]
		if !ok {
			return "", fmt.Errorf("unknown default port for scheme %s, specify the port explicitly", u.Scheme)
		}
		port = p
	}

	return u.Hostname() + ":" + port, nil
}

func probeHandler(config Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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

		exporter := &Exporter{
			ctx:     r.Context(),
			target:  target,
			timeout: timeout,
		}

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
		// Leave some headroom to respond before Prometheus closes the
		// connection, like the blackbox exporter does.
		if timeoutSeconds-scrapeTimeoutOffset.Seconds() > 0 {
			timeoutSeconds -= scrapeTimeoutOffset.Seconds()
		}
		if timeoutSeconds > 0 {
			return time.Duration(timeoutSeconds * float64(time.Second)), nil
		}
	}
	return defaultTimeout, nil
}

func getConfig() Config {
	config := Config{
		ListenAddress:  defaultListenAddress,
		DefaultTimeout: defaultTimeout,
	}

	if addr := os.Getenv("LISTEN_ADDRESS"); addr != "" {
		config.ListenAddress = addr
	}

	if timeout := os.Getenv("DEFAULT_TIMEOUT"); timeout != "" {
		if seconds, err := strconv.Atoi(timeout); err == nil && seconds > 0 {
			config.DefaultTimeout = time.Duration(seconds) * time.Second
		}
	}

	return config
}

func main() {
	config := getConfig()

	slog.Info("Starting server", "version", Version, "address", config.ListenAddress)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/probe", probeHandler(config))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(fmt.Sprintf(`<html>
			<head><title>SSL pubkey fingerprint exporter</title></head>
			<body>
			<h1>SSL pubkey fingerprint exporter</h1>
			<p>Version: %s</p>
			<p><a href="/probe?target=example.com:443">Probe example.com:443 for SSL pubkey fingerprint metrics</a></p>
			<p><a href='/metrics'>Metrics</a></p>
			</body>
			</html>`, Version)))
	})

	server := &http.Server{
		Addr:              config.ListenAddress,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		slog.Error("Server failed", "error", err)
		os.Exit(1)
	case <-ctx.Done():
		slog.Info("Shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			slog.Error("Graceful shutdown failed", "error", err)
			os.Exit(1)
		}
	}
}
