# SPKI fingerprint exporter

Prometheus exporter that reports the SHA-256 fingerprint of the Subject Public
Key Info (SPKI) in certificates presented by TLS services.

> [!NOTE]
> Previously named
> [`ssl-pubkey-fingerprint-exporter`](https://github.com/samuelb/ssl-pubkey-fingerprint-exporter).
> GitHub redirects old links, and releases still publish
> `basa/ssl-pubkey-fingerprint-exporter` as a Docker image alias.

## Usage

```bash
docker run -p 3000:3000 basa/spki-fingerprint-exporter
curl "http://localhost:3000/probe?target=example.com:443"
```

Or build from source with `make` (binaries land in `dist/`).

Targets are `host:port` or a URL. Without an explicit port, it is derived from
the URL scheme (`https`, `smtps`, `submissions`, `nntps`, `ldaps`, `domain-s`,
`ftps`, `imaps`, `pop3s`, `sips`); other protocols need the port spelled out.

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `LISTEN_ADDRESS` | Address to listen on | `:3000` |
| `DEFAULT_TIMEOUT` | Probe timeout: integer seconds or a Go duration (`750ms`, `15s`) | `10` |
| `MAX_CONCURRENT_PROBES` | Maximum simultaneous outbound TLS probes | `64` |

Invalid or non-positive timeout values are a configuration error at startup,
not a silent fallback.

## Helm

```bash
helm install spki-fingerprint-exporter ./helm
```

Add `--set serviceMonitor.enabled=true --set-string serviceMonitor.targets[0]=example.com:443`
to create a ServiceMonitor. Packaged charts are attached to GitHub releases.

Notes:
- `containerPort` sets both the container port and `LISTEN_ADDRESS`; do not add
  `LISTEN_ADDRESS` to `env` separately. Use `listenHost` to bind an interface.
- For exporter images predating the health endpoints, set
  `healthProbes.livenessPath` and `healthProbes.readinessPath` to `/`.

## Metrics

`/probe?target=example.com:443` returns:

```
spki_fingerprint{fingerprint="base64encodedsha256sumofspki=",target="example.com:443"} 1
probe_success 1
probe_duration_seconds 0.042
```

`probe_success` is `0` when the probe failed (unreachable host, TLS handshake
failure, invalid target), so alerts can distinguish a changed fingerprint from
a failed probe.

`/metrics` exposes operational metrics: `spki_fingerprint_exporter_active_probes`,
`spki_fingerprint_exporter_probes_total{result="success|failure"}`, and
`spki_fingerprint_exporter_rejected_probes_total`. Probes above
`MAX_CONCURRENT_PROBES` receive HTTP 503.

`/-/healthy` and `/-/ready` return HTTP 200 for container orchestrators.

## Prometheus

```yaml
scrape_configs:
  - job_name: "spki-fingerprint-exporter"
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
        replacement: spki-fingerprint-exporter:3000
```

Alert when the fingerprint changed (gated on `probe_success` so it only fires
on an unexpected fingerprint, not an unreachable target):

```
probe_success{instance="example.com:443"} == 1
unless on(instance)
spki_fingerprint{fingerprint="base64encodedsha256sumofspki="}
```

Alert when the probe failed: `probe_success == 0`

## Security considerations

`/probe` opens a TLS connection to any `host:port` a caller supplies, as is
common for blackbox-style exporters. Do not expose the exporter to untrusted
networks; restrict access to your Prometheus servers.

## Getting the SHA-256 fingerprint

From a PEM certificate:
```sh
openssl x509 -pubkey -noout -in certificate.pem | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64
```

From a private key:
```sh
openssl rsa -in certificate.key -pubout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64
```

From a live server:
```sh
servername=example.com; echo Q | openssl s_client -connect $servername:443 -servername $servername | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64
```

## Releasing

Trigger the *Release* workflow from the GitHub Actions tab (optionally
overriding the bump level). It derives the version from conventional commits,
updates the chart version, tags, publishes binaries and the packaged chart
with generated release notes, and pushes multi-arch Docker images.
