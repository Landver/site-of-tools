# syntax=docker/dockerfile:1

# ---- 1) Build: Tailwind CSS (standalone, no Node) + fully static Go binary ----
FROM golang:1.26 AS build
ARG TARGETARCH
ARG TAILWIND_VERSION=v4.3.2
WORKDIR /src

# Docker's TARGETARCH is amd64/arm64; Tailwind names its assets x64/arm64.
RUN case "$TARGETARCH" in \
      amd64) TW=x64 ;; \
      arm64) TW=arm64 ;; \
      *) echo "unsupported TARGETARCH=$TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /usr/local/bin/tailwindcss \
      "https://github.com/tailwindlabs/tailwindcss/releases/download/$TAILWIND_VERSION/tailwindcss-linux-$TW" \
    && chmod +x /usr/local/bin/tailwindcss

# Cache Go deps before copying the full tree.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN tailwindcss -i shared/static/css/input.css -o shared/static/css/styles.css --minify
# wasm_exec.js must come from the same toolchain that built cipher.wasm.
RUN mkdir -p shared/static/wasm \
    && GOOS=js GOARCH=wasm go build -trimpath -ldflags="-s -w" -o shared/static/wasm/cipher.wasm ./tools/ciphertools/wasm \
    && cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" shared/static/wasm/wasm_exec.js
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app .

# ---- 2) Runtime: distroless-static (CA certs + tzdata + nonroot, ~2 MB) ----
FROM gcr.io/distroless/static-debian12:nonroot
# cwd / (base default is /home/nonroot): the BINs mount at /tools/iptools/assets, so the
# repo-relative IP2LOCATION_* paths from .env resolve as in dev.
WORKDIR /
COPY --from=build /app /app
USER nonroot:nonroot
ENV APP_ENV=prod
EXPOSE 8080
ENTRYPOINT ["/app"]
