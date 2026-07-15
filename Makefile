# Load .env so targets see the config (dev convenience).
ifneq (,$(wildcard .env))
include .env
export
endif

TAILWIND_VERSION := v4.3.2
TAILWIND := ./shared/tailwindcss
# Map `uname -m` to Tailwind's release asset arch names (x64 / arm64).
UNAME_M := $(shell uname -m)
TW_ARCH := $(if $(filter aarch64 arm64,$(UNAME_M)),arm64,x64)
GOBIN := $(shell go env GOPATH 2>/dev/null)/bin

INPUT_CSS  := shared/static/css/input.css
OUTPUT_CSS := shared/static/css/styles.css

.PHONY: help deps tools hooks assets css css-watch dev run build test docker

help:
	@echo "Targets:"
	@echo "  deps       go mod tidy (populate go.mod + go.sum)"
	@echo "  tools      fetch Tailwind binary, install air, enable git hooks"
	@echo "  hooks      enable the pre-push test gate (git core.hooksPath)"
	@echo "  assets     download IP2Location LITE databases (needs token in .env)"
	@echo "  css        build minified stylesheet"
	@echo "  css-watch  rebuild stylesheet on change"
	@echo "  dev        run with live reload (APP_ENV=dev)"
	@echo "  run        run once, no reload"
	@echo "  test       go test ./... -race"
	@echo "  build      static production binary -> bin/server"
	@echo "  docker     docker compose up -d --build"

deps:
	go mod tidy

$(TAILWIND):
	curl -fsSL -o $(TAILWIND) https://github.com/tailwindlabs/tailwindcss/releases/download/$(TAILWIND_VERSION)/tailwindcss-linux-$(TW_ARCH)
	chmod +x $(TAILWIND)

tools: $(TAILWIND) hooks
	go install github.com/air-verse/air@latest

hooks:
	git config core.hooksPath .githooks
	@echo "git hooks enabled: .githooks (pre-push runs go vet + go test)"

assets:
	@bash iptools/download-assets.sh

css: $(TAILWIND)
	$(TAILWIND) -i $(INPUT_CSS) -o $(OUTPUT_CSS) --minify

css-watch: $(TAILWIND)
	$(TAILWIND) -i $(INPUT_CSS) -o $(OUTPUT_CSS) --watch

dev: css
	APP_ENV=dev $(GOBIN)/air

run:
	APP_ENV=dev go run .

test:
	go test ./... -race

build:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/server .

docker:
	docker compose up -d --build
