BINARY_NAME=urloot
GO=go
GOFLAGS=-v

.PHONY: all build clean test bench lint fmt install help

all: clean fmt test build

## build: Build the urloot binary
build:
	@echo "Building $(BINARY_NAME)..."
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o bin/$(BINARY_NAME) ./cmd/urloot

## clean: Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -rf bin/ $(BINARY_NAME) coverage.out coverage.html .urloot-config.yaml

## test: Run all tests with race detector
test:
	@echo "Running tests..."
	$(GO) test -v -race ./...

## bench: Run normalizer and SQLite store benchmarks
bench:
	@echo "Running benchmarks..."
	$(GO) test -bench=. -benchmem ./pkg/normalizer/... ./pkg/store/...

## fmt: Format and vet code
fmt:
	$(GO) fmt ./...
	$(GO) vet ./...

## lint: Run golangci-lint
lint:
	golangci-lint run ./...

## install: Install binary to $GOPATH/bin
install:
	CGO_ENABLED=0 $(GO) install ./cmd/urloot

## help: Show this help message
help:
	@echo "Usage: make [target]"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'
