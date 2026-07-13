# SSL public key fingerprint exporter

This Prometheus exporter allows you to monitor the public key fingerprints of
your SSL certificates.

## Table of Contents
- [Features](#features)
- [Building](#building)
- [Configuration](#configuration)
- [Docker](#docker)
- [Testing](#testing-with-curl)
- [Metrics](#metrics)
- [Prometheus](#prometheus)
- [Security considerations](#security-considerations)
- [Getting the SHA-256 fingerprint](#getting-the-sha-256-fingerprint)

## Features
- Monitor SSL certificate public key fingerprints
- Support for both domain:port and full URL targets
- Configurable timeout via environment variables
- Docker support
- Prometheus integration

## Building
```
make
```
The created binaries will end up in the folder `dist/`.

## Releasing

Releases are fully automated: trigger the *Release* workflow from the
GitHub Actions tab (optionally overriding the version bump level). The
workflow derives the next version from the conventional commits since
the last stable tag, updates `CHANGELOG.md` and the Helm chart version,
creates the tag and GitHub release with binaries, and pushes the
multi-arch Docker images.

## Configuration

The exporter can be configured using environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `LISTEN_ADDRESS` | Address to listen on | `:3000` |
| `DEFAULT_TIMEOUT` | Default timeout as integer seconds or a Go duration such as `750ms` or `15s` | `10` |

Invalid or non-positive timeout values cause the exporter to exit with a
configuration error rather than silently falling back to the default.

## Docker
```
docker pull basa/ssl-pubkey-fingerprint-exporter
docker run -p 3000:3000 basa/ssl-pubkey-fingerprint-exporter
```

## Testing with curl

You can test the exporter using curl to make HTTP requests to the probe endpoint:

```bash
# Test with a domain and port
curl "http://localhost:3000/probe?target=example.com:443"

# Test with a custom listen address
LISTEN_ADDRESS=:8080 ./ssl-pubkey-fingerprint-exporter
curl "http://localhost:8080/probe?target=example.com:443"
```

## Metrics

The response will be in Prometheus metrics format, showing the SSL certificate's public key fingerprint.

```
# HELP ssl_pubkey_fingerprint SSL certificate publickey SHA-256 fingerprint
# TYPE ssl_pubkey_fingerprint gauge
ssl_pubkey_fingerprint{fingerprint="base64encodedsha256sumofbinarypublickey=",target="example.com:443"} 1
# HELP probe_success Displays whether or not the probe was a success
# TYPE probe_success gauge
probe_success 1
# HELP probe_duration_seconds Returns how long the probe took to complete in seconds
# TYPE probe_duration_seconds gauge
probe_duration_seconds 0.042
```

`probe_success` is `0` when the target could not be probed (unreachable
host, TLS handshake failure, invalid target), so alerts can distinguish
a changed fingerprint from a failed probe.

### Targets

Targets can be given as `host:port` or as a URL. When no port is
specified, it is derived from the URL scheme. Supported schemes:
`https`, `smtps`, `submissions`, `nntps`, `ldaps`, `domain-s`, `ftps`,
`imaps`, `pop3s` and `sips`. For other protocols, specify the port
explicitly.

## Prometheus

### Scrape configuration
```yaml
scrape_configs:
  - job_name: "ssl-pubkey-fingerprint-exporter"
    metrics_path: /probe
    static_configs:
      - targets:
          - example.com:443
          - https://example.org
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: ssl-pubkey-fingerprint-exporter:3000
```

### Example PromQL queries

Alert when the fingerprint changed. The expression is gated on
`probe_success` so it only fires when the probe succeeded but returned
an unexpected fingerprint, not when the target was unreachable:
```
probe_success{instance="example.com:443"} == 1
unless on(instance)
ssl_pubkey_fingerprint{fingerprint="base64encodedsha256sumofbinarypublickey="}
```

Alert when the probe failed:
```
probe_success == 0
```

## Security considerations

The `/probe` endpoint opens a TCP/TLS connection to any `host:port` a
caller supplies, as is common for blackbox-style exporters. Do not
expose the exporter to untrusted networks (e.g. via a public ingress);
restrict access to your Prometheus servers.

## Getting the SHA-256 fingerprint

Extract public key sha256 fingerprint from PEM-encoded certificate file
```sh
openssl x509 -pubkey -noout -in certificate.pem | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64
```

Extract public key sha256 fingerprint from keyfile
```sh
openssl rsa -in certificate.key -pubout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64
```

Extract public key sha256 fingerprint from HTTP server
```sh
servername=example.com; echo Q | openssl s_client -connect $servername:443 -servername $servername | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64
```
