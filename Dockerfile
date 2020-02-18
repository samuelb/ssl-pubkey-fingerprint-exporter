FROM scratch

COPY dist/ssl_pubkey_fingerprint_exporter-linux-amd64 /bin/ssl_pubkey_fingerprint_exporter

EXPOSE 3000/tcp

ENTRYPOINT ["/bin/ssl_pubkey_fingerprint_exporter"]
