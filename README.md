# Huginn Net Profiler

[![CI](https://github.com/biandratti/huginn-net-profiler/actions/workflows/ci.yml/badge.svg)](https://github.com/biandratti/huginn-net-profiler/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.80+-orange.svg)](https://www.rust-lang.org/)

Web-based interface for testing and profiling TCP, HTTP and TLS connections using the [huginn-net](https://github.com/biandratti/huginn-net) library.

## Architecture

```
huginn-net-profiler/
├── profiler/
│   ├── profile-assembler/    # Central data aggregation service
│   ├── tcp-collector/        # TCP fingerprinting collector
│   ├── http-collector/       # HTTP fingerprinting collector
│   └── tls-collector/        # TLS fingerprinting collector
├── deployment/               # Docker deployment configuration
└── static/                   # Web UI assets
```

## Quick Start

1. Navigate to deployment directory:
```bash
cd deployment/
```

2. Generate SSL certificates (first time only):
```bash
# Install mkcert if not already installed
# Linux: sudo apt install libnss3-tools && wget https://github.com/FiloSottile/mkcert/releases/latest/download/mkcert-v1.4.4-linux-amd64 -O mkcert && chmod +x mkcert && sudo mv mkcert /usr/local/bin/
# macOS: brew install mkcert
# Windows: choco install mkcert

# Install local CA (one-time setup)
mkcert -install

# Generate trusted certificate for localhost
./generate-local-certs.sh
```

3. Configure network interface in `docker-compose.yml`:
```yaml
environment:
  - PROFILER_INTERFACE=your_interface_name  # e.g., eth0, wlan0
```

4. Deploy all services:
```bash
docker-compose up -d --build
```

5. Access the application:
- **Web interface**: https://localhost
- **API**: https://localhost/api
- **Traefik Dashboard**: http://localhost:8080

## System Requirements

- Docker and Docker Compose
- Network interface access (requires privileged containers)
- Linux host (for network capture capabilities)

## Development

Build manually:
```bash
cargo build --workspace --release
```

Run individual collectors:
```bash
sudo ./target/release/tcp-collector --interface eth0
sudo ./target/release/http-collector --interface br-xxxxx
sudo ./target/release/tls-collector --interface eth0
./target/release/profile-assembler
```
