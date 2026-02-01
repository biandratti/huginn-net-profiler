# Huginn Network Profiler - Deployment

## Network Interface Configuration

Each collector monitors a specific network interface via `PROFILER_INTERFACE`:
- **http-collector**: `br-XXXX` (Docker bridge) - captures traffic between Traefik and services
- **tcp-collector**: `wlp0s20f3` (host WiFi) - captures external internet traffic
- **tls-collector**: `wlp0s20f3` (host WiFi) - captures TLS handshakes and certificates
- Use `ip link show | grep huginn-net-bridge` to find the Docker bridge interface

## How to Run

### 1. Generate Local SSL Certificates (first time only)

For browser testing without security warnings, use `mkcert` to generate locally-trusted certificates:

```bash
cd deployment/

# Install mkcert (if not already installed)
# Linux: sudo apt install libnss3-tools && wget https://github.com/FiloSottile/mkcert/releases/latest/download/mkcert-v1.4.4-linux-amd64 -O mkcert && chmod +x mkcert && sudo mv mkcert /usr/local/bin/
# macOS: brew install mkcert
# Windows: choco install mkcert

# Install local CA (one-time setup)
mkcert -install

# Generate trusted certificate for localhost
./generate-local-certs.sh
```

### 2. Start Services

```bash
cd deployment/

# Option A: Use the start script (recommended - auto-detects bridge)
./start.sh

# Option B: Manual start (detect bridge first)
docker compose up --no-start  # Create networks first

# Auto-detect Docker bridge (most reliable)
export HUGINN_BRIDGE=$(ip link show | grep -E '^[0-9]+: br-[a-f0-9]{12}:' | tail -1 | cut -d: -f2 | awk '{print $1}')

echo "Using bridge: $HUGINN_BRIDGE"
docker compose up -d --build
```

## Access

- **Web interface**: https://localhost
- **API**: https://localhost/api
- **Traefik Dashboard**: http://localhost:8080
