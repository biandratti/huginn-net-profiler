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
RUN cargo build --release -p http-collector

# Copy the actual source code and compile
COPY profiler/http-collector/src ./profiler/http-collector/src
RUN cargo build --release -p http-collector

# ---- Final Stage ----
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y libpcap0.8 ca-certificates netcat-openbsd

# Copy the compiled binary from the build stage
COPY --from=builder /usr/src/app/target/release/http-collector /usr/local/bin/http-collector

# Expose the port the server will listen on
EXPOSE 8080

# Set the default command
CMD ["http-collector"] 