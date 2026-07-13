# spki-fingerprint-exporter

Prometheus exporter that reports the SHA-256 fingerprint of the Subject Public
Key Info (SPKI) in certificates presented by TLS services. Use it to alert
when a service starts presenting an unexpected public key — for example after
an unnoticed certificate replacement or a man-in-the-middle.

This chart deploys the exporter and can optionally create a
[Prometheus Operator](https://prometheus-operator.dev/) ServiceMonitor that
probes a list of TLS targets.

- Project: <https://github.com/samuelb/spki-fingerprint-exporter>
- Images: `basa/spki-fingerprint-exporter` (Docker Hub) and
  `ghcr.io/samuelb/spki-fingerprint-exporter`

## Installing

```bash
helm install spki-fingerprint-exporter oci://ghcr.io/samuelb/charts/spki-fingerprint-exporter
```

To probe targets via the Prometheus Operator, enable the ServiceMonitor:

```bash
helm install spki-fingerprint-exporter oci://ghcr.io/samuelb/charts/spki-fingerprint-exporter \
  --set serviceMonitor.enabled=true \
  --set-string 'serviceMonitor.targets[0]=example.com:443'
```

Targets are `host:port` or a URL (`https://example.org`). Without an explicit
port, it is derived from the URL scheme.

## Values

| Key | Description | Default |
|-----|-------------|---------|
| `replicaCount` | Number of exporter replicas | `1` |
| `image.repository` | Image repository | `basa/spki-fingerprint-exporter` |
| `image.tag` | Image tag | chart `appVersion` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `nameOverride` | Override the chart name | `""` |
| `fullnameOverride` | Override the full resource name | `""` |
| `service.type` | Service type | `ClusterIP` |
| `service.port` | Service port | `3000` |
| `containerPort` | Port the exporter listens on; also sets `LISTEN_ADDRESS` | `3000` |
| `listenHost` | Optional interface/address to bind (the container port is appended) | `""` |
| `healthProbes.livenessPath` | Liveness probe path | `/-/healthy` |
| `healthProbes.readinessPath` | Readiness probe path | `/-/ready` |
| `env` | Additional environment variables (e.g. `DEFAULT_TIMEOUT`, `MAX_CONCURRENT_PROBES`) | `[]` |
| `podSecurityContext` | Pod security context | non-root, `RuntimeDefault` seccomp |
| `securityContext` | Container security context | read-only root FS, all capabilities dropped |
| `serviceMonitor.enabled` | Create a ServiceMonitor for the Prometheus Operator | `false` |
| `serviceMonitor.targets` | TLS targets to probe (required when enabled) | `[]` |
| `serviceMonitor.interval` | Scrape interval | `30s` |
| `serviceMonitor.scrapeTimeout` | Scrape timeout | `10s` |
| `serviceMonitor.additionalLabels` | Extra labels on the ServiceMonitor (e.g. to match a Prometheus selector) | `{}` |
| `ingress.enabled` | Create an Ingress | `false` |
| `ingress.pathType` | Ingress path type | `ImplementationSpecific` |
| `ingress.annotations` | Ingress annotations | `{}` |
| `ingress.hosts` | Ingress hosts and paths | see `values.yaml` |
| `ingress.tls` | Ingress TLS configuration | `[]` |
| `resources` | Container resource requests/limits | `{}` |
| `nodeSelector` | Node selector | `{}` |
| `tolerations` | Tolerations | `[]` |
| `affinity` | Affinity rules | `{}` |

Notes:

- `containerPort` sets both the container port and the `LISTEN_ADDRESS`
  environment variable; do not add `LISTEN_ADDRESS` to `env` separately
  (the chart fails rendering if you do).
- For exporter images predating the health endpoints, set
  `healthProbes.livenessPath` and `healthProbes.readinessPath` to `/`.

## Metrics

Each ServiceMonitor target is scraped via `/probe?target=...` and yields:

```
spki_fingerprint{fingerprint="base64encodedsha256sumofspki=",target="example.com:443"} 1
probe_success 1
probe_duration_seconds 0.042
```

`probe_success` is `0` when the probe failed, so alerts can distinguish a
changed fingerprint from an unreachable target:

```
probe_success{instance="example.com:443"} == 1
unless on(instance)
spki_fingerprint{fingerprint="base64encodedsha256sumofspki="}
```

See the [project README](https://github.com/samuelb/spki-fingerprint-exporter)
for how to compute the expected fingerprint with `openssl`, operational
metrics on `/metrics`, and configuration details.

## Security considerations

`/probe` opens a TLS connection to any `host:port` a caller supplies, as is
common for blackbox-style exporters. Do not expose the exporter outside the
cluster; restrict access to your Prometheus servers.
