# Load .env so targets see the config (dev convenience).
ifneq (,$(wildcard .env))
include .env
export
endif

TAILWIND_VERSION := v4.3.2
TAILWIND := ./shared/tailwindcss
# Map `uname -s` / `uname -m` to Tailwind's release asset names.
# OS: Darwin -> macos, everything else -> linux (prod host). Arch: x64 / arm64.
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)
TW_OS   := $(if $(filter Darwin,$(UNAME_S)),macos,linux)
TW_ARCH := $(if $(filter aarch64 arm64,$(UNAME_M)),arm64,x64)
GOBIN := $(shell go env GOPATH 2>/dev/null)/bin

INPUT_CSS  := shared/static/css/input.css
OUTPUT_CSS := shared/static/css/styles.css

.PHONY: help deps tools hooks assets mongo-init css css-watch wasm dev run build test docker

help:
	@echo "Targets:"
	@echo "  deps       go mod tidy (populate go.mod + go.sum)"
	@echo "  tools      fetch Tailwind binary, install air, enable git hooks"
	@echo "  hooks      enable the pre-push test gate (git core.hooksPath)"
	@echo "  assets     download IP2Location LITE databases (needs token in .env)"
	@echo "  mongo-init create the site-of-tools database on the Mongo server (needs MONGODB_URI)"
	@echo "  css        build minified stylesheet"
	@echo "  css-watch  rebuild stylesheet on change"
	@echo "  wasm       build the in-browser engine for cipher.corpberry.com"
	@echo "  dev        run with live reload (APP_ENV=dev)"
	@echo "  run        run once, no reload"
	@echo "  test       go test ./... -race"
	@echo "  build      static production binary -> bin/server"
	@echo "  docker     docker compose up -d --build"

deps:
	go mod tidy

$(TAILWIND):
	curl -fsSL -o $(TAILWIND) https://github.com/tailwindlabs/tailwindcss/releases/download/$(TAILWIND_VERSION)/tailwindcss-$(TW_OS)-$(TW_ARCH)
	chmod +x $(TAILWIND)

tools: $(TAILWIND) hooks
	# Pinned per CLAUDE.md (air v1.65.x) — @latest would drift.
	go install github.com/air-verse/air@v1.65.3

hooks:
	git config core.hooksPath .githooks
	@echo "git hooks enabled: .githooks (pre-push runs go vet + go test)"

assets:
	@bash tools/iptools/download-assets.sh

# One-off: materialize the site-of-tools database on the shared Mongo server.
# Mongo creates databases lazily, so this makes it exist up front. Reads
# MONGODB_URI from .env (included above); run from a host that can reach the
# server. Optional now that the app writes on first request (request log +
# lookup history) — it just provisions up front. See docs/ARCHITECTURE.md §10.
mongo-init:
	go run mongoinit.go

css: $(TAILWIND)
	$(TAILWIND) -i $(INPUT_CSS) -o $(OUTPUT_CSS) --minify

css-watch: $(TAILWIND)
	$(TAILWIND) -i $(INPUT_CSS) -o $(OUTPUT_CSS) --watch

# The in-browser engine for cipher.corpberry.com: tools/ciphertools compiled to
# WebAssembly, plus the wasm_exec.js loader copied from the SAME toolchain (the
# two must match, which is why it is copied here rather than committed). Both
# are gitignored and embedded via shared/static, the styles.css pattern.
WASM_DIR := shared/static/wasm
wasm:
	@mkdir -p $(WASM_DIR)
	GOOS=js GOARCH=wasm go build -trimpath -ldflags="-s -w" -o $(WASM_DIR)/cipher.wasm ./tools/ciphertools/wasm
	cp "$$(go env GOROOT)/lib/wasm/wasm_exec.js" $(WASM_DIR)/wasm_exec.js

dev: css wasm
	APP_ENV=dev $(GOBIN)/air

run:
	APP_ENV=dev go run .

# Also compiles the wasm engine: its main package is js-only, so a plain
# `go test ./...` never builds it and would pass while it is broken.
test:
	go test ./... -race
	GOOS=js GOARCH=wasm go vet ./tools/ciphertools ./tools/ciphertools/wasm

# Depends on css: the binary embeds shared/static (all:static), and styles.css is
# gitignored/generated — without this a fresh-clone `make build` embeds a missing
# or stale stylesheet (a 404 in prod). The Docker build already builds CSS first.
build: css wasm
	CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/server .

docker:
	docker compose up -d --build
