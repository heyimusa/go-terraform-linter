# Build stage
FROM golang:1.21-alpine AS builder

# Install necessary packages for building
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o terraform-linter ./cmd/linter

# Final stage
FROM scratch

# Copy CA certificates from builder stage
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy timezone data
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy the binary
COPY --from=builder /app/terraform-linter /usr/local/bin/terraform-linter

# Set the default working directory
WORKDIR /workspace

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/terraform-linter"]

# Default command
CMD ["--help"] 