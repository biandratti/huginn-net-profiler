#!/bin/bash

PCAP_DIR="/shared/pcaps"
CURRENT_PCAP="/shared/current.pcap"
INTERFACE="ens4"
ROTATION_TIME=30  # seconds per file
MAX_FILES=5       # Keep only last 5 files

echo "📡 Starting continuous network dump"
echo "🔗 Interface: $INTERFACE"
echo "📁 Directory: $PCAP_DIR"
echo "🔄 Rotation: ${ROTATION_TIME}s"

# Create directory
mkdir -p "$PCAP_DIR"

# Cleanup old files function
cleanup() {
    ls -t "$PCAP_DIR"/*.pcap 2>/dev/null | tail -n +$((MAX_FILES + 1)) | xargs -r rm -f
}

# Main dump loop
while true; do
    TIMESTAMP=$(date +%H%M%S)
    PCAP_FILE="$PCAP_DIR/dump_${TIMESTAMP}.pcap"
    
    echo "📦 Dumping to: $(basename "$PCAP_FILE")"
    
    # Capture for 30 seconds
    timeout ${ROTATION_TIME}s tcpdump \
        -i "$INTERFACE" \
        -w "$PCAP_FILE" \
        -s 0 \
        "port 443" \
        2>/dev/null || true
    
    # Update current.pcap symlink if file exists
    if [ -f "$PCAP_FILE" ] && [ -s "$PCAP_FILE" ]; then
        ln -sf "$PCAP_FILE" "$CURRENT_PCAP"
        echo "✅ Updated: $(basename "$PCAP_FILE") ($(du -h "$PCAP_FILE" | cut -f1))"
        cleanup
    else
        rm -f "$PCAP_FILE" 2>/dev/null || true
        echo "⚠️  Empty dump, keeping previous"
    fi
    
    sleep 1
done 