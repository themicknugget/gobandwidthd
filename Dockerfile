# Build stage with libpcap-dev installed
FROM golang:1.22-bookworm AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y gcc musl-dev liblinear-dev libpcap-dev git cmake make

# Clone and build a specific version of nDPI
WORKDIR /ndpi
RUN git clone https://github.com/ntop/nDPI.git . \
    && ./autogen.sh \
    && ./configure \
    && make \
    && make install

WORKDIR /app

# Copy go mod and sum files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the application's source code
COPY . .

# Build the application
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o gobandwidth .

# Final stage
FROM debian:12-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y libpcap0.8 libndpi-dev liblinear-dev && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/gobandwidth /gobandwidth

# Command to run
ENTRYPOINT ["/gobandwidth"]