# Huginn Network Profiler - Deployment

## Network Interface Configuration

Each collector monitors a specific network interface via `PROFILER_INTERFACE`:
- **http-collector**: `br-XXXX` (Docker bridge) - captures traffic between Traefik and services
- **tcp-collector**: `wlp0s20f3` (host WiFi) - captures external internet traffic
- **tls-collector**: `wlp0s20f3` (host WiFi) - captures TLS handshakes and certificates
- Use `ip link show | grep huginn-net-bridge` to find the Docker bridge interface

## How to Run

```bash
cd deployment/

docker compose up --no-start  # Create networks first

# Auto-detect Docker bridge (most reliable)
export HUGINN_BRIDGE=$(ip link show | grep -E '^[0-9]+: br-[a-f0-9]{12}:' | tail -1 | cut -d: -f2 | awk '{print $1}')

echo "Using bridge: $HUGINN_BRIDGE"
docker compose up -d --build
```

## Access

- **Web interface**: https://huginn-net.duckdns.org
- **API**: https://huginn-net.duckdns.org/api
- **Traefik Dashboard**: http://localhost:8080
