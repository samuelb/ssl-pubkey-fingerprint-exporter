VERSION     ?= 0.1.0
BINARY_DIR  ?= dist
BINARY_NAME ?= ssl_pubkey_fingerprint_exporter
PLATFORMS   ?= linux/amd64 windows/amd64 darwin/amd64

GO         ?= go
GOOPTS     ?=
GOHOSTOS   ?= $(shell $(GO) env GOHOSTOS)
GOHOSTARCH ?= $(shell $(GO) env GOHOSTARCH)

DOCKER            ?= docker
DOCKER_REPO       ?= samuelb
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
	GOOS=$(_OS) GOARCH=$(_ARCH) $(GO) build \
		 -o $(BINARY_DIR)/$(BINARY_NAME)-$(_OS)-$(_ARCH)

docker: $(DOCKER_ARCH)
	$(DOCKER) build \
		--build-arg VERSION=$(VERSION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		-t $(DOCKER_REPO)/$(DOCKER_IMAGE_NAME):$(VERSION) .

release: test $(PLATFORMS) docker
	$(DOCKER) tag \
		$(DOCKER_REPO)/$(DOCKER_IMAGE_NAME):$(VERSION) \
		$(DOCKER_REPO)/$(DOCKER_IMAGE_NAME):latest
	$(SHA256SUM) $(BINARY_DIR)/$(BINARY_NAME)* | sed "s|$(BINARY_DIR)/||" > $(BINARY_DIR)/sha256sums.txt

publish: release
	$(DOCKER) push $(DOCKER_REPO)/$(DOCKER_IMAGE_NAME):$(VERSION)
	$(DOCKER) push $(DOCKER_REPO)/$(DOCKER_IMAGE_NAME):latest

clean:
	$(GO) clean
	rm -rf $(BINARY_DIR)
