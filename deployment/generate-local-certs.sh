#!/bin/bash
# Generate locally-trusted SSL certificates for localhost using mkcert

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="${SCRIPT_DIR}/certs"

echo "Generating local SSL certificates for localhost..."

# Check if mkcert is installed
if ! command -v mkcert &> /dev/null; then
    echo "Error: mkcert is not installed."
    echo ""
    echo "Please install mkcert first:"
    echo "  Linux: sudo apt install libnss3-tools && wget https://github.com/FiloSottile/mkcert/releases/latest/download/mkcert-v1.4.4-linux-amd64 -O mkcert && chmod +x mkcert && sudo mv mkcert /usr/local/bin/"
    echo "  macOS: brew install mkcert"
    echo "  Windows: choco install mkcert"
    echo ""
    echo "Then run: mkcert -install"
    exit 1
fi

# Create certs directory if it doesn't exist
mkdir -p "${CERTS_DIR}"

# Generate certificate for localhost
mkcert -key-file "${CERTS_DIR}/server.key" -cert-file "${CERTS_DIR}/server.crt" \
    localhost 127.0.0.1 ::1

# Set proper permissions
chmod 644 "${CERTS_DIR}/server.key" "${CERTS_DIR}/server.crt"

echo ""
echo "✓ Certificates generated successfully!"
echo "  Certificate: ${CERTS_DIR}/server.crt"
echo "  Private key: ${CERTS_DIR}/server.key"
echo ""
echo "You can now start the services with: docker compose up -d"
