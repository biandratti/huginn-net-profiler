#!/bin/bash
set -e

# Auto-detect Docker bridge (most reliable)
export HUGINN_BRIDGE=$(ip link show | grep -E '^[0-9]+: br-[a-f0-9]{12}:' | tail -1 | cut -d: -f2 | awk '{print $1}')

if [ -z "$HUGINN_BRIDGE" ]; then
    echo "Error: Could not detect Docker bridge. Make sure Docker is running and has created a bridge network."
    exit 1
fi

echo "Using bridge: $HUGINN_BRIDGE"

# Start docker compose with the detected bridge
docker compose up -d "$@"
