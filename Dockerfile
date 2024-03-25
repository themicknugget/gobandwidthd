# Build stage with libpcap-dev installed
FROM golang:1.20-alpine AS builder

# Install build dependencies
RUN apk add --no-cache gcc musl-dev libpcap-dev ndpi-dev

WORKDIR /app

# Copy go mod and sum files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the application's source code
COPY . .

# Build the application
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o gobandwidth .

# Final stage
FROM alpine

# Install runtime dependencies
RUN apk --no-cache add libpcap-dev ndpi-dev

COPY --from=builder /app/gobandwidth /gobandwidth

# Command to run
ENTRYPOINT ["/gobandwidth"]
