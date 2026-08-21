BIN     := evidenced
PKG     := ./cmd/evidenced
VERSION ?= dev
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build build-all lint test clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BIN) $(PKG)

build-all:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BIN)-linux-amd64 $(PKG)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BIN)-linux-arm64 $(PKG)

lint:
	golangci-lint run ./...

test:
	go test -race ./...

clean:
	rm -rf bin
