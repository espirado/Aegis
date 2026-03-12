# AEGIS Proxy Docker Image
# Multi-stage build: compile Go binary, embed ONNX model, minimal runtime

# ── Stage 1: Build ──
FROM golang:1.22-bookworm AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -o aegis ./cmd/aegis/

# ── Stage 2: Runtime ──
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r aegis && useradd -r -g aegis aegis

WORKDIR /app

# Copy binary
COPY --from=builder /build/aegis .

# Copy ONNX models (must be built/downloaded before docker build)
COPY ml/models/*.onnx /app/models/

# Copy config
COPY configs/aegis.yaml /app/configs/

# Set ownership
RUN chown -R aegis:aegis /app

USER aegis

EXPOSE 8080 9090

ENTRYPOINT ["./aegis"]
