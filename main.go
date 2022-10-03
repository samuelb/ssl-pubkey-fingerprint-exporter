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
)

type Exporter struct {
	target  string
	timeout time.Duration
	w       http.ResponseWriter
}

func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- pubkeyFingerprint
}

func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	target, err := parseTarget(e.target)
	if err != nil {
		log.Error(err)
		http.Error(e.w, fmt.Sprintf("Failed to parse target %s: %s", target, err), http.StatusInternalServerError)
		return
	}

	fingerprint, err := getFingerprint(target, e.timeout)
	if err != nil {
		log.Error(err)
		http.Error(e.w, fmt.Sprintf("Failed to get publickey fingerprint from %s: %s", target, err), http.StatusInternalServerError)
		return
	}

	ch <- prometheus.MustNewConstMetric(
		pubkeyFingerprint, prometheus.GaugeValue, 1, fingerprint, target,
	)
}

func getFingerprint(target string, timeout time.Duration) (string, error) {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", target, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return "", err
	}
	defer conn.Close()

	connstate := conn.ConnectionState()
	leafcert := connstate.PeerCertificates[0]
	der, err := x509.MarshalPKIXPublicKey(leafcert.PublicKey)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(der)
	return base64.StdEncoding.EncodeToString(hash[0:]), nil
}

func parseTarget(target string) (parsedTarget string, err error) {
	if !strings.Contains(target, "://") {
		target = "//" + target
	}

	u, err := url.Parse(target)
	if err != nil {
		return "", err
	}

	port := u.Port()

	if port == "" {
		if u.Scheme != "" {
			p, err := net.LookupPort("tcp", u.Scheme)
			if err != nil {
				return "", err
			}
			port = strconv.Itoa(p)
		} else {
			return "", errors.New("Can't parse target. Protocol scheme or port number is required")
		}
	}

	return u.Hostname() + ":" + port, nil
}

func probeHandler(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")

	timeoutSeconds, err := getScrapeTimeout(r, w)
	if err != nil {
		log.Error(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	timeout := time.Duration((timeoutSeconds) * 1e9)

	exporter := &Exporter{
		target:  target,
		timeout: timeout,
		w:       w,
	}

	registry := prometheus.NewRegistry()
	registry.MustRegister(exporter)

	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	h.ServeHTTP(w, r)
}

func getScrapeTimeout(r *http.Request, w http.ResponseWriter) (float64, error) {
	var timeoutSeconds float64
	if v := r.Header.Get("X-Prometheus-Scrape-Timeout-Seconds"); v != "" {
		var err error
		timeoutSeconds, err = strconv.ParseFloat(v, 64)
		if err != nil {
			return -1, fmt.Errorf("Failed to parse timeout from Prometheus header: %s", err)
		}
	} else {
		timeoutSeconds = 10
	}
	if timeoutSeconds == 0 {
		timeoutSeconds = 10
	}
	return timeoutSeconds, nil
}

func main() {
	listenAddress := ":3000"

	http.Handle("/metrics", promhttp.Handler())
	http.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
		probeHandler(w, r)
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html>
			<head><title>SSL pubkey fingerprint exporter/title></head>
			<body>
			<h1>SSL pubkey fingerprint exporter</h1>
			<p><a href="/probe?target=example.com:443">Probe example.com:443 for SSL pubkey fingerprint metrics</a></p>
			<p><a href='/metrics'>Metrics</a></p>
			</body>
			</html>`))
	})

	log.Info("Listening on", listenAddress)
	log.Fatal(http.ListenAndServe(listenAddress, nil))
}
