# Stage 1: Builder
# Use a modern Rust version based on Debian Bookworm
FROM rust:1.82 as builder

WORKDIR /usr/src/app

# Install build-time dependencies
RUN apt-get update && apt-get install -y libpcap-dev libssl-dev pkg-config

# First, copy only the manifests to leverage Docker cache.
COPY Cargo.toml Cargo.lock ./
COPY profiler/http-collector/Cargo.toml ./profiler/http-collector/
COPY profiler/profile-assembler/Cargo.toml ./profiler/profile-assembler/
COPY profiler/tcp-collector/Cargo.toml ./profiler/tcp-collector/
COPY profiler/tls-collector/Cargo.toml ./profiler/tls-collector/

# Create dummy main.rs files for all binary crates in the workspace.
# This allows us to build and cache all dependencies without building the final binaries.
RUN mkdir -p profiler/http-collector/src && echo "fn main() {}" > profiler/http-collector/src/main.rs
RUN mkdir -p profiler/profile-assembler/src && echo "fn main() {}" > profiler/profile-assembler/src/main.rs
RUN mkdir -p profiler/tcp-collector/src && echo "fn main() {}" > profiler/tcp-collector/src/main.rs
RUN mkdir -p profiler/tls-collector/src && echo "fn main() {}" > profiler/tls-collector/src/main.rs

# Build and cache all dependencies for the workspace.
RUN cargo build --release --workspace

# Now, copy the actual source code.
# This layer will only be re-built if the source code changes.
COPY . .

# Build the specific binary for this service, which will be very fast
# as all dependencies are already cached.
RUN cargo build --release -p tls-collector

# Stage 2: Final Image
# Use the corresponding modern Debian version
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y libpcap0.8 libssl3 && rm -rf /var/lib/apt/lists/*

# Copy the compiled binary from the builder stage
COPY --from=builder /usr/src/app/target/release/tls-collector /usr/local/bin/tls-collector

CMD ["/usr/local/bin/tls-collector"] 