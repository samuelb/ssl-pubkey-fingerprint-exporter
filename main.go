package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

var (
	pubkeyFingerprint = prometheus.NewDesc(
		"ssl_pubkey_fingerprint",
		"SSL certificate publickey SHA-256 fingerprint",
		[]string{"fingerprint", "target"}, nil,
	)

	// Default configuration
	defaultListenAddress = ":3000"
	defaultTimeout       = 10 * time.Second
)

type Config struct {
	ListenAddress  string
	DefaultTimeout time.Duration
}

type Exporter struct {
	target  string
	timeout time.Duration
}

func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- pubkeyFingerprint
}

func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	target, err := parseTarget(e.target)
	if err != nil {
		log.WithFields(log.Fields{
			"target": e.target,
			"error":  err,
		}).Error("Failed to parse target")
		return
	}

	fingerprint, err := getFingerprint(target, e.timeout)
	if err != nil {
		log.WithFields(log.Fields{
			"target": target,
			"error":  err,
		}).Error("Failed to get publickey fingerprint")
		return
	}

	ch <- prometheus.MustNewConstMetric(
		pubkeyFingerprint, prometheus.GaugeValue, 1, fingerprint, target,
	)
}

func getFingerprint(target string, timeout time.Duration) (string, error) {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", target, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return "", fmt.Errorf("failed to establish TLS connection: %w", err)
	}
	defer conn.Close()

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
		if u.Scheme != "" {
			p, err := net.LookupPort("tcp", u.Scheme)
			if err != nil {
				return "", fmt.Errorf("failed to lookup port for scheme %s: %w", u.Scheme, err)
			}
			port = strconv.Itoa(p)
		} else {
			return "", errors.New("protocol scheme or port number is required")
		}
	}

	return u.Hostname() + ":" + port, nil
}

func probeHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	if target == "" {
		http.Error(w, "target parameter is required", http.StatusBadRequest)
		return
	}

	timeoutSeconds, err := getScrapeTimeout(r)
	if err != nil {
		log.WithError(err).Error("Failed to get scrape timeout")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	timeout := time.Duration(timeoutSeconds * float64(time.Second))

	exporter := &Exporter{
		target:  target,
		timeout: timeout,
	}

	registry := prometheus.NewRegistry()
	registry.MustRegister(exporter)

	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	h.ServeHTTP(w, r)
}

func getScrapeTimeout(r *http.Request) (float64, error) {
	if v := r.Header.Get("X-Prometheus-Scrape-Timeout-Seconds"); v != "" {
		timeoutSeconds, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return 0, fmt.Errorf("failed to parse timeout from Prometheus header: %w", err)
		}
		if timeoutSeconds > 0 {
			return timeoutSeconds, nil
		}
	}
	return float64(defaultTimeout.Seconds()), nil
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

	// Configure logging
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})

	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/probe", probeHandler)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html>
			<head><title>SSL pubkey fingerprint exporter</title></head>
			<body>
			<h1>SSL pubkey fingerprint exporter</h1>
			<p><a href="/probe?target=example.com:443">Probe example.com:443 for SSL pubkey fingerprint metrics</a></p>
			<p><a href='/metrics'>Metrics</a></p>
			</body>
			</html>`))
	})

	log.WithField("address", config.ListenAddress).Info("Starting server")
	log.Fatal(http.ListenAndServe(config.ListenAddress, nil))
}
