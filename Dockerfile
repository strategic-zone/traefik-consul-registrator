FROM golang:1.21-alpine AS builder

# Install git and dependencies
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

# Copy the existing go.mod and go.sum files
COPY go.mod go.sum* ./

# Make sure go.sum exists (empty if needed)
RUN touch go.sum

# Use the exact dependencies from the original go.mod file
RUN go mod download

# Copy the source code
COPY . .

# Build the application, ignoring vendoring
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -mod=mod -o traefik-consul-registrator .

# Final stage: minimal runtime image
FROM alpine:3.19

# Install CA certificates and timezone data
RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# Copy the compiled binary
COPY --from=builder /app/traefik-consul-registrator .

# Create non-root user for potential future use
RUN addgroup -S appgroup && \
    adduser -S appuser -G appgroup

# We'll run as root to ensure Docker socket access
# In production, consider using a more secure approach with proper GID mapping
# USER root is the default so we don't need to specify it

# Set the entrypoint
ENTRYPOINT ["/app/traefik-consul-registrator"]