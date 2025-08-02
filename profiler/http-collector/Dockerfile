# Stage 1: Builder
# Use a modern Rust version based on Debian Bookworm
FROM rust:1.82 as builder

WORKDIR /usr/src/app

# Install build-time dependencies
RUN apt-get update && apt-get install -y libpcap-dev libssl-dev pkg-config

# Copy the entire project context
COPY . .

# Build the specific package for this service
RUN cargo build --release -p http-collector

# Stage 2: Final Image
# Use the corresponding modern Debian version
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y libpcap0.8 && rm -rf /var/lib/apt/lists/*

# Copy the compiled binary from the builder stage
COPY --from=builder /usr/src/app/target/release/http-collector /usr/local/bin/http-collector

CMD ["http-collector"] 