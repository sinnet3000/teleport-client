# Binary name
BINARY=teleport-client

# Build metadata. Tagged builds report the tag; local builds report the
# distance from the latest tag and a dirty suffix when tracked files change.
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
BINARY_VERSION := $(patsubst v%,%,$(VERSION))

# Build flags
LDFLAGS=-ldflags "-X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}"

# Platforms
PLATFORMS=linux/amd64 linux/arm64 linux/arm darwin/amd64 darwin/arm64 windows/amd64 freebsd/amd64 freebsd/arm64 openbsd/amd64 openbsd/arm64

# Output directories
DIST_DIR=bin

.PHONY: all build clean test vet version help

all: clean build

build:
	@mkdir -p ${DIST_DIR}
	@set -e; for platform in ${PLATFORMS}; do \
		OS=$$(echo $$platform | cut -f1 -d'/'); \
		ARCH=$$(echo $$platform | cut -f2 -d'/'); \
		echo "Building for $$OS/$$ARCH..."; \
		if [ "$$OS" = "windows" ]; then \
			GOOS=$$OS GOARCH=$$ARCH go build ${LDFLAGS} -o ${DIST_DIR}/${BINARY}_${BINARY_VERSION}_$${OS}_$${ARCH}.exe .; \
		else \
			GOOS=$$OS GOARCH=$$ARCH go build ${LDFLAGS} -o ${DIST_DIR}/${BINARY}_${BINARY_VERSION}_$${OS}_$${ARCH} .; \
		fi; \
	done
	@echo "Build complete! Binaries are in ${DIST_DIR}/"

test:
	go test ./...

vet:
	go vet ./...

version:
	@printf 'version=%s commit=%s build_date=%s\n' "${VERSION}" "${COMMIT}" "${BUILD_DATE}"

clean:
	@rm -rf ${DIST_DIR}
	@echo "Cleaned ${DIST_DIR}/ directory"

# Show help
help:
	@echo "Available targets:"
	@echo "  all      - Clean and build all binaries (default)"
	@echo "  build    - Build binaries for all platforms"
	@echo "  test     - Run tests"
	@echo "  vet      - Run go vet"
	@echo "  clean    - Remove build artifacts"
	@echo "  help     - Show this help message"
