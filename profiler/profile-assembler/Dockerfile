FROM rust:1.82 as builder

WORKDIR /usr/src/app

# First, copy only the manifests to leverage Docker cache.
COPY Cargo.toml Cargo.lock ./
COPY profiler/http-collector/Cargo.toml ./profiler/http-collector/
COPY profiler/profile-assembler/Cargo.toml ./profiler/profile-assembler/
COPY profiler/tcp-collector/Cargo.toml ./profiler/tcp-collector/
COPY profiler/tls-collector/Cargo.toml ./profiler/tls-collector/

# Create dummy main.rs files for all binary crates in the workspace.
RUN mkdir -p profiler/http-collector/src && echo "fn main() {}" > profiler/http-collector/src/main.rs
RUN mkdir -p profiler/profile-assembler/src && echo "fn main() {}" > profiler/profile-assembler/src/main.rs
RUN mkdir -p profiler/tcp-collector/src && echo "fn main() {}" > profiler/tcp-collector/src/main.rs
RUN mkdir -p profiler/tls-collector/src && echo "fn main() {}" > profiler/tls-collector/src/main.rs

# Build and cache all dependencies for the workspace.
RUN cargo build --release --workspace

# Now, copy the actual source code.
COPY . .

# Build the specific binary for this service
RUN cargo build --release -p profile-assembler

# Final stage
FROM debian:bookworm-slim

# Install netcat for healthcheck
RUN apt-get update && apt-get install -y netcat-openbsd && rm -rf /var/lib/apt/lists/*

# Copy binary
COPY --from=builder /usr/src/app/target/release/profile-assembler /usr/local/bin/profile-assembler

CMD ["/usr/local/bin/profile-assembler"]