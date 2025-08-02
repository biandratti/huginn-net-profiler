# ---- Compilation Stage ----
FROM rust:1.82 as builder

# Install build dependencies
RUN apt-get update && apt-get install -y libpcap-dev libssl-dev pkg-config

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
RUN cargo build --release -p tls-collector

# Copy the actual source code and compile
COPY profiler/tls-collector/src ./profiler/tls-collector/src
RUN cargo build --release -p tls-collector

# ---- Final Stage ----
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y libpcap0.8 ca-certificates netcat-openbsd

# Copy the compiled binary from the build stage
COPY --from=builder /usr/src/app/target/release/tls-collector /usr/local/bin/tls-collector

# Set the default command to run the collector
CMD ["tls-collector"] 