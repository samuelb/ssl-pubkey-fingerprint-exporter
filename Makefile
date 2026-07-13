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
SHA256SUM         ?= $(if $(shell command -v sha256sum 2>/dev/null),sha256sum,shasum -a 256)

ARTIFACTS := $(foreach platform,$(PLATFORMS),$(BINARY_DIR)/$(BINARY_NAME)-$(subst /,-,$(platform)))

LDFLAGS := -ldflags "-X main.Version=$(VERSION)"

_OS   = $(word 1, $(subst /, ,$@))
_ARCH = $(word 2, $(subst /, ,$@))

.PHONY: all build test clean build-all checksums docker release version $(PLATFORMS)

all: build

build: $(GOHOSTOS)/$(GOHOSTARCH)

build-all: $(PLATFORMS)

test:
	$(GO) vet $(GOOPTS) ./...
	$(GO) test $(GOOPTS) -race ./...

$(PLATFORMS):
	CGO_ENABLED=0 GOOS=$(_OS) GOARCH=$(_ARCH) $(GO) build $(GOOPTS) $(LDFLAGS) \
		 -o $(BINARY_DIR)/$(BINARY_NAME)-$(_OS)-$(_ARCH)

docker:
	$(DOCKER) build \
		--build-arg VERSION=$(VERSION) \
		-t $(DOCKER_REPO)/$(DOCKER_IMAGE_NAME):$(VERSION) .

checksums: build-all
	$(SHA256SUM) $(ARTIFACTS) | sed "s|$(BINARY_DIR)/||" > $(BINARY_DIR)/sha256sums.txt

release: test checksums

clean:
	$(GO) clean
	rm -rf $(BINARY_DIR)

version:
	@echo $(VERSION)
