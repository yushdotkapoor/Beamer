BINARY_NAME=beamer
GO=/opt/homebrew/opt/go@1.24/bin/go
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS=-ldflags "-s -w -X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)"

.PHONY: build build-host clean run test lint deps

# Build for local machine (development)
build:
	$(GO) build $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/beamer

# Cross-compile for 2012 MacBook Pro (Intel, macOS Big Sur)
build-host:
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(LDFLAGS) -o bin/$(BINARY_NAME)-darwin-amd64 ./cmd/beamer

run: build
	./bin/$(BINARY_NAME)

test:
	$(GO) test -v -race -count=1 ./...

test-coverage:
	$(GO) test -v -race -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html

lint:
	golangci-lint run ./...

clean:
	rm -rf bin/ coverage.out coverage.html data/

deps:
	$(GO) mod download
	$(GO) mod verify
