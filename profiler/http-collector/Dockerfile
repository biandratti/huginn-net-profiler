# Stage 1: Builder
# Use a modern Rust version based on Debian Bookworm
FROM rust:1.82 as builder

WORKDIR /usr/src/app

# Install build-time dependencies
RUN apt-get update && apt-get install -y libpcap-dev libssl-dev pkg-config

# First, copy only the manifests to leverage Docker cache.
COPY huginn-net-profiler/Cargo.toml huginn-net-profiler/Cargo.lock ./
COPY huginn-net-profiler/profiler/http-collector/Cargo.toml ./profiler/http-collector/
COPY huginn-net-profiler/profiler/profile-assembler/Cargo.toml ./profiler/profile-assembler/
COPY huginn-net-profiler/profiler/tcp-collector/Cargo.toml ./profiler/tcp-collector/
COPY huginn-net-profiler/profiler/tls-collector/Cargo.toml ./profiler/tls-collector/
COPY huginn-net/Cargo.toml ./huginn-net/
COPY huginn-net/benches/ ./huginn-net/benches/
COPY huginn-net/config/ ./huginn-net/config/

# Create dummy main.rs files for all binary crates in the workspace.
# This allows us to build and cache all dependencies without building the final binaries.
RUN mkdir -p profiler/http-collector/src && echo "fn main() {}" > profiler/http-collector/src/main.rs
RUN mkdir -p profiler/profile-assembler/src && echo "fn main() {}" > profiler/profile-assembler/src/main.rs
RUN mkdir -p profiler/tcp-collector/src && echo "fn main() {}" > profiler/tcp-collector/src/main.rs
RUN mkdir -p profiler/tls-collector/src && echo "fn main() {}" > profiler/tls-collector/src/main.rs
RUN mkdir -p huginn-net/src && echo "pub fn dummy() {}" > huginn-net/src/lib.rs

# Build and cache all dependencies for the workspace.
RUN cargo build --release --workspace

# Now, copy the actual source code.
# This layer will only be re-built if the source code changes.
COPY huginn-net-profiler/ .
COPY huginn-net/src/ ./huginn-net/src/
COPY huginn-net/benches/ ./huginn-net/benches/
COPY huginn-net/examples/ ./huginn-net/examples/
COPY huginn-net/config/ ./huginn-net/config/

# Build the specific binary for this service, which will be very fast
# as all dependencies are already cached.
RUN cargo build --release -p http-collector

# Stage 2: Final Image
# Use the corresponding modern Debian version
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y libpcap0.8 libssl3 && rm -rf /var/lib/apt/lists/*

# Copy the compiled binary from the builder stage
COPY --from=builder /usr/src/app/target/release/http-collector /usr/local/bin/http-collector

CMD ["/usr/local/bin/http-collector"] 