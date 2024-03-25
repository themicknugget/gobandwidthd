# Build stage with libpcap-dev, ndpi-dev, and liblinear-dev from Alpine Edge
FROM golang:1.20-alpine AS builder

# Add Edge repository for ndpi and liblinear packages
RUN echo "@edge http://nl.alpinelinux.org/alpine/edge/main" >> /etc/apk/repositories
RUN echo "@edge http://nl.alpinelinux.org/alpine/edge/testing" >> /etc/apk/repositories
RUN echo "@edge http://nl.alpinelinux.org/alpine/edge/community" >> /etc/apk/repositories

# Install build dependencies
# Use the @edge tag for packages only available in the edge repository
RUN apk add --no-cache gcc musl-dev libpcap-dev ndpi-dev@edge liblinear-dev@edge

WORKDIR /app

# Copy go mod and sum files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the application's source code
COPY . .

# Build the application
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o gobandwidth .

# Final stage using a specific version of Alpine
FROM alpine

# Add Edge repository for runtime dependencies, if needed
RUN echo "@edge http://nl.alpinelinux.org/alpine/edge/main" >> /etc/apk/repositories
RUN echo "@edge http://nl.alpinelinux.org/alpine/edge/testing" >> /etc/apk/repositories
RUN echo "@edge http://nl.alpinelinux.org/alpine/edge/community" >> /etc/apk/repositories

# Install runtime dependencies with @edge tag if they are from edge repository
RUN apk --no-cache add libpcap ndpi@edge liblinear@edge

COPY --from=builder /app/gobandwidth /gobandwidth

# Command to run
ENTRYPOINT ["/gobandwidth"]
