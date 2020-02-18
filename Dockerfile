FROM golang:1.13-buster AS build

ADD . /src

RUN cd /src && make linux/amd64


FROM scratch

COPY --from=build /src/dist/ssl_pubkey_fingerprint_exporter-linux-amd64 /ssl_pubkey_fingerprint_exporter

EXPOSE 3000/tcp

ENTRYPOINT ["/ssl_pubkey_fingerprint_exporter"]
