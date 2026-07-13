# syntax=docker/dockerfile:1

ARG GO_VERSION=1.24
FROM golang:${GO_VERSION} AS build

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w -X main.Version=${VERSION}" \
    -o /out/ssl-pubkey-fingerprint-exporter .

FROM scratch

COPY <<EOT /etc/passwd
ssl-exporter:x:1000:1000:ssl-exporter:/app:/sbin/nologin
EOT

COPY <<EOT /etc/group
ssl-exporter:x:1000:
EOT

COPY --from=build /out/ssl-pubkey-fingerprint-exporter /ssl-pubkey-fingerprint-exporter

USER 1000:1000
EXPOSE 3000/tcp

ENTRYPOINT ["/ssl-pubkey-fingerprint-exporter"]
