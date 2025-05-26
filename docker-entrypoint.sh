#!/bin/bash
set -e

# Check if we're running the genkey command
if [ "$1" = "genkey" ] || [ "$1" = "--genkey" ]; then
    echo "=== mtproxy-rs Key Generation ==="
    if [ "$1" = "genkey" ]; then
        # Convert legacy subcommand to flag syntax
        shift
        exec mtproxy-rs --genkey "$@"
    else
        # Already using flag syntax
        exec mtproxy-rs "$@"
    fi
fi

echo "=== MTProxy-RS Container Starting ==="
echo "Time: $(date)"
echo "Hostname: $(hostname)"

# Show network information for debugging
echo "=== Network Information ==="
echo "Container IP: $(hostname -i 2>/dev/null || echo 'N/A')"
echo "Network interfaces:"
ip addr show 2>/dev/null || ifconfig 2>/dev/null || echo "Network interface tools not available"

# Show DNS configuration for IP detection services
echo "=== DNS Configuration ==="
cat /etc/resolv.conf 2>/dev/null || echo "DNS config not available"

# Test external connectivity for IP detection
echo "=== External Connectivity Test ==="
if curl -s --connect-timeout 5 https://ipv4.icanhazip.com > /dev/null 2>&1; then
    echo "✅ External IP detection services reachable"
    PUBLIC_IP=$(curl -s --connect-timeout 5 https://ipv4.icanhazip.com 2>/dev/null || echo "N/A")
    echo "   Detected public IP: $PUBLIC_IP"
else
    echo "⚠️  External IP detection services may not be reachable"
    echo "   MTProxy-RS will use fallback detection methods"
fi

# Wait a moment for network to be ready
sleep 2

echo "=== Starting MTProxy-RS ==="

# Use environment variables for configuration with sensible defaults
STATS_PORT=${STATS_PORT:-8888}
HTTP_PORTS=${HTTP_PORTS:-443}
WORKERS=${WORKERS:-1}
RUST_LOG=${RUST_LOG:-info}
PORT=${PORT:-443}

# Generate SECRET if not provided
if [ -z "$SECRET" ]; then
    echo "SECRET not provided, generating random secret..."
    SECRET=$(mtproxy-rs --genkey)
    echo "Generated SECRET: $SECRET"
fi

# Additional arguments from environment
EXTRA_ARGS=${@:-}

# Build the command
CMD="mtproxy-rs --stats-port $STATS_PORT --http-ports $HTTP_PORTS -M $WORKERS --mtproto-secret $SECRET"

# Add TAG if provided
if [ -n "$TAG" ]; then
    CMD="$CMD --ad-tag $TAG"
    echo "Using promotion TAG: $TAG"
fi

# Add external IP if provided
if [ -n "$EXTERNAL_IP" ]; then
    CMD="$CMD --ip $EXTERNAL_IP"
    echo "Using external IP: $EXTERNAL_IP"
fi

# Add extra arguments if provided
if [ -n "$EXTRA_ARGS" ]; then
    CMD="$CMD $EXTRA_ARGS"
fi

echo "Command: $CMD"
echo "Environment: RUST_LOG=$RUST_LOG"
echo ""
echo "=== MTProxy-RS Configuration ==="
echo "    Secret: $SECRET"
echo "    User-facing port: $PORT"
if [ -z "$EXTERNAL_IP" ]; then
    echo "    Server IP: Auto-detect"
else
    echo "    Server IP: $EXTERNAL_IP"
fi
echo ""

# Export logging level
export RUST_LOG

# Execute the proxy
exec $CMD 