# ---- Compilation Stage ----
FROM rust:1.82 as builder

# Install build dependencies
RUN apt-get update && apt-get install -y libssl-dev pkg-config

# Create a working directory
WORKDIR /usr/src/app

# Copy manifests from the workspace root and ALL members
COPY Cargo.toml Cargo.lock ./
COPY profiler/tls-collector/Cargo.toml ./profiler/tls-collector/
COPY profiler/http-collector/Cargo.toml ./profiler/http-collector/
COPY profiler/profile-assembler/Cargo.toml ./profiler/profile-assembler/

# Create a dummy src for each workspace member so cargo can resolve them
WORKDIR /usr/src/app/profiler/tls-collector
RUN mkdir src && echo "fn main() {}" > src/main.rs
WORKDIR /usr/src/app/profiler/http-collector
RUN mkdir src && echo "fn main() {}" > src/main.rs
WORKDIR /usr/src/app/profiler/profile-assembler
RUN mkdir src && echo "fn main() {}" > src/main.rs
WORKDIR /usr/src/app
RUN cargo build --release -p profile-assembler

# Copy the actual source code and compile
COPY profiler/profile-assembler/src ./profiler/profile-assembler/src
RUN cargo build --release -p profile-assembler

# ---- Final Stage ----
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y ca-certificates netcat-openbsd

# Copy the compiled binary
COPY --from=builder /usr/src/app/target/release/profile-assembler /usr/local/bin/profile-assembler

# Expose the API port
EXPOSE 8000

# Default command
CMD ["profile-assembler"] 