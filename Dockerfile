FROM golang:1.24 AS build

RUN mkdir -p /rootfs/etc && \
    echo 'ssl-exporter:x:1000:1000:ssl-exporter:/app:/sbin/nologin' > /rootfs/etc/passwd && \
    echo 'ssl-exporter:x:1000:' > /rootfs/etc/group

ADD . /src
RUN cd /src && make

FROM scratch

COPY --from=build /rootfs /
COPY --from=build /src/dist/ssl-pubkey-fingerprint-exporter-* /ssl-pubkey-fingerprint-exporter

USER 1000:1000
EXPOSE 3000/tcp

ENTRYPOINT ["/ssl-pubkey-fingerprint-exporter"]
