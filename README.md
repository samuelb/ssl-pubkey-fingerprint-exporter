# SSL public key fingerprint exporter

This Prometheus exporter allows you to monitor the public key fingerprint of
your SSL certificates.

## Building
```
make
```
The created binaries will and up in the folder `dist/`.

## Docker
```
docker pull samuel/ssl_pubkey_fingerprint_exporter
docker run -p 3000:3000 samuel/ssl_pubkey_fingerprint_exporter
```

## Metrics
```
# HELP ssl_pubkey_fingerprint SSL certificate publickey SHA-256 fingerprint
# TYPE ssl_pubkey_fingerprint gauge
ssl_pubkey_fingerprint{fingerprint="base64encodedsha256sumofbinarypublickey=",target="example.com:443"} 1
```

## Prometheus
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
        replacement: ssl-fingerprint-exporter:3000
```
