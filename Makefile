VERSION     ?= 0.3.0
BINARY_DIR  ?= dist
BINARY_NAME ?= ssl-pubkey-fingerprint-exporter
PLATFORMS   ?= linux/amd64 windows/amd64 darwin/amd64 darwin/arm64

GO         ?= go
GOOPTS     ?=
GOHOSTOS   ?= $(shell $(GO) env GOHOSTOS)
GOHOSTARCH ?= $(shell $(GO) env GOHOSTARCH)

DOCKER            ?= docker
DOCKER_REPO       ?= basa
DOCKER_IMAGE_NAME ?= ssl-pubkey-fingerprint-exporter
DOCKER_ARCH       ?= linux/amd64

SHA256SUM         ?= sha256sum

GIT_COMMIT ?= $(shell git rev-parse --short HEAD)

_OS   = $(word 1, $(subst /, ,$@))
_ARCH = $(word 2, $(subst /, ,$@))


build: $(GOHOSTOS)/$(GOHOSTARCH)

build-all: $(PLATFORMS)

test:
	$(GO) test

$(PLATFORMS):
	CGO_ENABLED=0 GOOS=$(_OS) GOARCH=$(_ARCH) $(GO) build \
		 -o $(BINARY_DIR)/$(BINARY_NAME)-$(_OS)-$(_ARCH)

docker:
	$(DOCKER) build \
		--build-arg VERSION=$(VERSION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		-t $(DOCKER_REPO)/$(DOCKER_IMAGE_NAME):$(VERSION) .

release: test $(PLATFORMS)
	$(SHA256SUM) $(BINARY_DIR)/$(BINARY_NAME)* | sed "s|$(BINARY_DIR)/||" > $(BINARY_DIR)/sha256sums.txt

clean:
	$(GO) clean
	rm -rf $(BINARY_DIR)
