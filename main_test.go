package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseTarget(t *testing.T) {
	var tests = []struct {
		input       string
		output      string
		shouldError bool
	}{
		{"https://example.com", "example.com:443", false},
		{"ldaps://example.com", "example.com:636", false},
		{"https://example.com:1234", "example.com:1234", false},
		{"example.com:1234", "example.com:1234", false},
		{"", "", true},
		{"example.com", "", true},
		{"//example.com", "", true},
		{"foobar://example.com", "", true},
	}

	for _, test := range tests {
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
		{"header below offset", "0.2", 200 * time.Millisecond, false},
		{"negative header", "-1", defaultTimeout, false},
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

	handler := probeHandler(Config{DefaultTimeout: 5 * time.Second})

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
