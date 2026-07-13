VERSION     ?= $(shell git describe --tags --always --dirty)
BINARY_DIR  ?= dist
BINARY_NAME ?= ssl-pubkey-fingerprint-exporter
PLATFORMS   ?= linux/386 linux/amd64 linux/arm64 linux/mips linux/mipsle linux/mips64 linux/mips64le linux/ppc64 linux/ppc64le linux/riscv64 linux/s390x netbsd/386 netbsd/amd64 openbsd/amd64 windows/amd64 darwin/amd64 darwin/arm64

GO         ?= go
GOOPTS     ?=
GOHOSTOS   ?= $(shell $(GO) env GOHOSTOS)
GOHOSTARCH ?= $(shell $(GO) env GOHOSTARCH)

DOCKER            ?= docker
DOCKER_REPO       ?= basa
DOCKER_IMAGE_NAME ?= ssl-pubkey-fingerprint-exporter
SHA256SUM         ?= sha256sum

LDFLAGS := -ldflags "-X main.Version=$(VERSION)"

_OS   = $(word 1, $(subst /, ,$@))
_ARCH = $(word 2, $(subst /, ,$@))

.PHONY: all build test clean build-all

all: build

build: $(GOHOSTOS)/$(GOHOSTARCH)

build-all: $(PLATFORMS)

test:
	$(GO) vet ./...
	$(GO) test -race ./...

$(PLATFORMS):
	CGO_ENABLED=0 GOOS=$(_OS) GOARCH=$(_ARCH) $(GO) build $(LDFLAGS) \
		 -o $(BINARY_DIR)/$(BINARY_NAME)-$(_OS)-$(_ARCH)

docker:
	$(DOCKER) build \
		--build-arg VERSION=$(VERSION) \
		-t $(DOCKER_REPO)/$(DOCKER_IMAGE_NAME):$(VERSION) .

release: test $(PLATFORMS)
	$(SHA256SUM) $(BINARY_DIR)/$(BINARY_NAME)* | sed "s|$(BINARY_DIR)/||" > $(BINARY_DIR)/sha256sums.txt

clean:
	$(GO) clean
	rm -rf $(BINARY_DIR)

version:
	@echo $(VERSION)
