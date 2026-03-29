# Stage 1: Build
FROM golang:1.26 AS builder

WORKDIR /app

# Copy go.mod and go.sum first for better layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the container example binary
RUN CGO_ENABLED=0 GOOS=linux go build -o /server ./example/container/

# Stage 2: Runtime
FROM gcr.io/distroless/static-debian12

# Copy the binary
COPY --from=builder /server /server

# mTLS port
EXPOSE 8443
# Health check port
EXPOSE 8080

# Certificates are mounted at runtime — NEVER baked into the image
# Mount points:
#   /certs/chain.crt     — server certificate chain (leaf + intermediate)
#   /certs/server.key    — server private key
#   /certs/root-ca.crt   — root CA certificate for client trust pool

ENV SERVER_CHAIN_FILE=/certs/chain.crt
ENV SERVER_KEY_FILE=/certs/server.key
ENV ROOT_CA_FILE=/certs/root-ca.crt

ENTRYPOINT ["/server"]
