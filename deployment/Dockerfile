FROM rust:1.80-slim AS builder

WORKDIR /usr/src/app
COPY . .

RUN apt-get update && \
    apt-get install -y pkg-config libssl-dev libpcap-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build the huginn-api binary
RUN cargo build --release --bin huginn-api

FROM debian:bookworm-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y libssl-dev libpcap-dev ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy the huginn-api binary instead of tcp-profiler
COPY --from=builder /usr/src/app/target/release/huginn-api /app/
COPY --from=builder /usr/src/app/static /app/static

EXPOSE 3000

# Run huginn-api with default interface
CMD ["./huginn-api", "--interface", "eth0"]