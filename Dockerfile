# syntax=docker/dockerfile:1

# ---- 1) CSS: Tailwind standalone binary (no Node/npm). Arch-aware. ----
FROM debian:12-slim AS css
ARG TARGETARCH
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# TARGETARCH (amd64/arm64) is provided by buildkit; Tailwind names assets x64/arm64.
RUN case "$TARGETARCH" in \
      amd64) TW=x64 ;; \
      arm64) TW=arm64 ;; \
      *) echo "unsupported TARGETARCH=$TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /usr/local/bin/tailwindcss \
      "https://github.com/tailwindlabs/tailwindcss/releases/download/v4.3.2/tailwindcss-linux-$TW" \
    && chmod +x /usr/local/bin/tailwindcss
# Tailwind scans templates across the projects for class names.
COPY shared ./shared
COPY site ./site
COPY iptolocation ./iptolocation
RUN tailwindcss -i shared/static/css/input.css -o shared/static/css/styles.css --minify

# ---- 2) Go: fully static build; embeds the project incl. the built styles.css ----
FROM golang:1.26 AS build
WORKDIR /src
# go.mod + go.sum must exist — run `make deps` before building.
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=css /src/shared/static/css/styles.css shared/static/css/styles.css
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app .

# ---- 3) Runtime: distroless-static (CA certs + tzdata + nonroot, ~2 MB) ----
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /app /app
USER nonroot:nonroot
ENV APP_ENV=prod
EXPOSE 8080
ENTRYPOINT ["/app"]
