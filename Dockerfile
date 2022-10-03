FROM golang:1.19-buster AS build

ADD . /src

RUN cd /src && make linux/amd64


FROM scratch

COPY --from=build /src/dist/ssl-pubkey-fingerprint-exporter-linux-amd64 /ssl-pubkey-fingerprint-exporter

EXPOSE 3000/tcp

ENTRYPOINT ["/ssl-pubkey-fingerprint-exporter"]
