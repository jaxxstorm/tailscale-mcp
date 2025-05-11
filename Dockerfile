# syntax=docker/dockerfile:1

FROM cgr.dev/chainguard/go:latest AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

# Copy the remaining project files
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o /src/tailscale-mcp .

FROM cgr.dev/chainguard/static:latest


# Copy the binary from the builder stage
COPY --from=builder /src/tailscale-mcp /usr/local/bin/tailscale-mcp

EXPOSE 8080

# Launch
ENTRYPOINT ["/usr/local/bin/tailscale-mcp"]
