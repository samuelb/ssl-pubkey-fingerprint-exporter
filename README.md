# SSL public key fingerprint exporter

This Prometheus exporter allows you to monitor the public key fingerprints of
your SSL certificates.

## Building
```
make
```
The created binaries will and up in the folder `dist/`.

## Docker
```
docker pull basa/ssl_pubkey_fingerprint_exporter
docker run -p 3000:3000 basa/ssl_pubkey_fingerprint_exporter
```

## Metrics
```
# HELP ssl_pubkey_fingerprint SSL certificate publickey SHA-256 fingerprint
# TYPE ssl_pubkey_fingerprint gauge
ssl_pubkey_fingerprint{fingerprint="base64encodedsha256sumofbinarypublickey=",target="example.com:443"} 1
```

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

### Example PromQL query
```
absent(ssl_pubkey_fingerprint{fingerprint="base64encodedsha256sumofbinarypublickey",target="example.com:443"})
```

## Getting the SHA-256 fingerprint

Extract public key sha265 fingerprint from PEM-encoded certificate file
```sh
openssl x509 -pubkey -noout -in certificate.pem | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64
```

Extract public key sha265 fingerprint from keyfile
```sh
openssl rsa -in certificate.key -pubout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64
```

Extract public key sha265 fingerprint from HTTP server
```sh
servername=example.com; echo Q | openssl s_client -connect $servername:443 -servername $servername | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64
```
