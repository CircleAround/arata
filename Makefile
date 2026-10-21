# arata のビルド・テスト・lint。Go は $HOME/.local/go に展開した公式 tarball を想定 (README 参照)。
GO ?= $(firstword $(wildcard $(HOME)/.local/go/bin/go) $(shell command -v go 2>/dev/null))
GOLANGCI ?= $(firstword $(wildcard $(HOME)/go/bin/golangci-lint) $(shell command -v golangci-lint 2>/dev/null))
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
BIN := bin

.PHONY: build build-local test lint vet fmt clean

## build: linux/arm64 と linux/amd64 の静的バイナリを bin/ に作る
build:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/arata-linux-arm64 ./cmd/arata
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/arata-linux-amd64 ./cmd/arata

## build-local: このホスト向けのバイナリを bin/arata に作る
build-local:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/arata ./cmd/arata

## test: 全テスト (ユニット + コマンドレベル e2e)
test:
	$(GO) test ./...

## vet: go vet
vet:
	$(GO) vet ./...

## lint: go vet + golangci-lint (入っていれば)
lint: vet
	@if [ -n "$(GOLANGCI)" ]; then $(GOLANGCI) run ./...; else echo "golangci-lint not found; skipped (go vet only)"; fi

fmt:
	$(GO) fmt ./...

clean:
	rm -rf $(BIN)
