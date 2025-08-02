# Stage 1: Builder
# Use a modern Rust version based on Debian Bookworm
FROM rust:1.82 as builder

WORKDIR /usr/src/app

# Copy the entire project context
COPY . .

# Build the specific package for this service
RUN cargo build --release -p profile-assembler

# Stage 2: Final Image
# Use the corresponding modern Debian version
FROM debian:bookworm-slim

# Install modern runtime dependencies
RUN apt-get update && apt-get install -y libssl3 && rm -rf /var/lib/apt/lists/*

# Copy the compiled binary from the builder stage
COPY --from=builder /usr/src/app/target/release/profile-assembler /usr/local/bin/profile-assembler

EXPOSE 8000
CMD ["profile-assembler"] 