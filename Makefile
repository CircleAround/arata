# arata のビルド・テスト・lint。Go は $HOME/.local/go に展開した公式 tarball を想定 (README 参照)。
GO ?= $(firstword $(wildcard $(HOME)/.local/go/bin/go) $(shell command -v go 2>/dev/null))
GOLANGCI ?= $(firstword $(wildcard $(HOME)/go/bin/golangci-lint) $(shell command -v golangci-lint 2>/dev/null))
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
BIN := bin

.PHONY: build build-local test lint vet fmt clean scan-sensitive scan-sensitive-history scan-sensitive-github

CMDS := arata aratam

## build: arata と aratam の linux/arm64 と linux/amd64 の静的バイナリを bin/ に作る
build:
	for c in $(CMDS); do \
		CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/$$c-linux-arm64 ./cmd/$$c || exit 1; \
		CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/$$c-linux-amd64 ./cmd/$$c || exit 1; \
	done

## build-local: このホスト向けのバイナリを bin/arata と bin/aratam に作る
build-local:
	for c in $(CMDS); do CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/$$c ./cmd/$$c || exit 1; done

## test: 全テスト (ユニット + コマンドレベル e2e)
test:
	$(GO) test ./...

## vet: go vet
vet:
	$(GO) vet ./...

## lint: go vet + golangci-lint (入っていれば。設定は .golangci.yml。gosec と staticcheck を含み、CI の sast.yml と同じ)
lint: vet
	@if [ -n "$(GOLANGCI)" ]; then $(GOLANGCI) run ./...; else echo "golangci-lint not found; skipped (go vet only)"; fi

fmt:
	$(GO) fmt ./...

# 公開できない情報の検査 (ADR 0036、docs/sensitive-scan.md)。語の一覧はリポジトリの外に置く
SENSITIVE_PATTERNS_FILE ?= $(HOME)/.config/arata/sensitive-patterns.txt
GITLEAKS ?= $(BIN)/gitleaks
GITLEAKS_FLAGS := --no-banner --redact -c .gitleaks.toml

$(BIN)/gitleaks:
	tools/install-gitleaks.sh $(BIN)

## scan-sensitive: 作業ツリーの禁止語と、まだコミットしていない変更の秘密を調べる (pre-commit に使える)
scan-sensitive: $(GITLEAKS)
	$(GO) run ./tools/wordscan -patterns $(SENSITIVE_PATTERNS_FILE) -mode tree
	$(GITLEAKS) git $(GITLEAKS_FLAGS) --pre-commit .

## scan-sensitive-history: 全履歴の禁止語と秘密を調べる (CI と同じ)
scan-sensitive-history: $(GITLEAKS)
	$(GO) run ./tools/wordscan -patterns $(SENSITIVE_PATTERNS_FILE) -mode history
	$(GITLEAKS) git $(GITLEAKS_FLAGS) --log-opts=--all .
	git log --all --format=%B | $(GITLEAKS) stdin $(GITLEAKS_FLAGS)

## scan-sensitive-github: GitHub 上の本文 (PR・Issue・コメント・Release) を調べる。gh の認証が要る
scan-sensitive-github: $(GITLEAKS)
	tools/github-text.sh CircleAround/arata $(BIN)/github-text
	$(GITLEAKS) dir $(GITLEAKS_FLAGS) $(BIN)/github-text
	$(GO) run ./tools/wordscan -patterns $(SENSITIVE_PATTERNS_FILE) -mode dir -dir $(BIN)/github-text -github-notes

clean:
	rm -rf $(BIN)
