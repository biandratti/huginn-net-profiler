FROM rust:1.82 as builder

WORKDIR /usr/src/app

# Copy only this project
COPY profiler/profile-assembler/Cargo.toml ./
COPY profiler/profile-assembler/src ./src

# Build independently 
RUN cargo build --release

# Final stage
FROM debian:bookworm-slim

# Copy binary
COPY --from=builder /usr/src/app/target/release/profile-assembler /usr/local/bin/profile-assembler

CMD ["/usr/local/bin/profile-assembler"]