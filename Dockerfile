FROM golang:1.24 AS build

ADD . /src
RUN cd /src && make

FROM scratch

COPY <<EOT /etc/passwd
ssl-exporter:x:1000:1000:ssl-exporter:/app:/sbin/nologin
EOT

COPY <<EOT /etc/group
ssl-exporter:x:1000:
EOT

COPY --from=build /src/dist/ssl-pubkey-fingerprint-exporter-* /ssl-pubkey-fingerprint-exporter

USER 1000:1000
EXPOSE 3000/tcp

ENTRYPOINT ["/ssl-pubkey-fingerprint-exporter"]