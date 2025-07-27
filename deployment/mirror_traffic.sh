#!/bin/bash
set -e

echo "🚀 Setting up traffic mirroring for huginn..."

# Create virtual interface for huginn to capture post-traefik traffic
echo "📡 Creating huginn-mirror interface..."
if ! ip link show huginn-mirror >/dev/null 2>&1; then
    ip link add huginn-mirror type dummy
    ip link set huginn-mirror up
    ip addr add 169.254.1.1/24 dev huginn-mirror
    echo "✅ huginn-mirror interface created"
else
    echo "ℹ️  huginn-mirror interface already exists"
fi

# Setup traffic control to mirror outbound traffic from port 443 to huginn-mirror
echo "🔄 Setting up traffic mirroring..."

# Clean existing rules
tc qdisc del dev huginn-mirror root 2>/dev/null || true
tc qdisc del dev ens4 root 2>/dev/null || true

# Add qdisc to huginn-mirror (our target interface)
tc qdisc add dev huginn-mirror root handle 1: prio

# Add qdisc to ens4 (source interface) 
tc qdisc add dev ens4 root handle 1: prio

# Mirror traffic going out from port 443 (traefik responses) to huginn-mirror
# This should capture traffic AFTER traefik has processed it
tc filter add dev ens4 parent 1: protocol ip prio 1 u32 \
    match ip sport 443 0xffff \
    action mirred egress mirror dev huginn-mirror

echo "✅ Traffic mirroring configured:"
echo "   📡 Source: ens4 (outbound port 443)"
echo "   🎯 Target: huginn-mirror"
echo "   📊 huginn will capture post-traefik traffic"

# Show interface status
echo ""
echo "🔍 Interface status:"
ip link show huginn-mirror | grep -E "(huginn-mirror|UP|DOWN)"
echo ""

# Show traffic control rules
echo "📋 Traffic control rules:"
tc filter show dev ens4

echo "🎉 Traffic mirroring setup complete!"
echo "   huginn should now capture HTTP/2 traffic on huginn-mirror interface" 