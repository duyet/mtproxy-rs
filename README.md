# mtproxy-rs

A high-performance Telegram MTProxy implementation in Rust.

[![Rust CI](https://github.com/duyet/mtproxy-rs/actions/workflows/rust-ci.yml/badge.svg)](https://github.com/duyet/mtproxy-rs/actions/workflows/rust-ci.yml)
[![Cross Platform Build](https://github.com/duyet/mtproxy-rs/actions/workflows/cross-platform-build.yml/badge.svg)](https://github.com/duyet/mtproxy-rs/actions/workflows/cross-platform-build.yml)
[![Docker Build & Publish](https://github.com/duyet/mtproxy-rs/actions/workflows/docker-build.yml/badge.svg)](https://github.com/duyet/mtproxy-rs/actions/workflows/docker-build.yml)

## Features

### Core Features
- **Memory Safe** - Written in pure Rust with zero unsafe code
- **High Performance** - Optimized async I/O with Tokio runtime
- **Docker Support** - Production-ready containerization
- **HTTP Stats API** - Real-time monitoring with Prometheus metrics
- **Compatible** - Drop-in replacement for original MTProxy
- **Cross-platform** - Linux, macOS, Windows support

### Security Features
- **Authentication Rate Limiting** - Automatic IP blocking after failed attempts
- **Timestamp Validation** - Protection against replay attacks
- **Stats Endpoint Authentication** - Optional bearer token protection
- **Configurable Limits** - Per-IP and global connection limits
- **Non-root Execution** - Automatic privilege dropping
- **Network Interface Stats** - Real-time traffic monitoring

### Operational Features
- **Configurable Timeouts** - All constants configurable via config file
- **Graceful Shutdown** - Clean connection termination
- **Health Checks** - Built-in liveness probes
- **Structured Logging** - JSON logs with configurable levels
- **Memory Efficient** - Optimized dependencies, small binary size

## Quick Start

### Docker

```bash
# Generate a secret
export SECRET=$(openssl rand -hex 16)

# Run using GitHub Container Registry
docker run -d -p 443:443 -p 8888:8888 \
  -e EXTRA_ARGS="-S $SECRET" \
  --name mtproxy-rs \
  ghcr.io/duyet/mtproxy-rs:latest

# Or generate a key with the built-in tool
docker run --rm ghcr.io/duyet/mtproxy-rs --genkey
```

### Docker Compose

```bash
git clone https://github.com/duyet/mtproxy-rs
cd mtproxy-rs
docker-compose up -d
```

### From Source

```bash
# Install & build
git clone https://github.com/duyet/mtproxy-rs
cd mtproxy-rs
cargo build --release

# Generate secret & run
SECRET=$(openssl rand -hex 16)
./target/release/mtproxy-rs -p 8888 -H 443 -S $SECRET -M 1

# Or use built-in key generator
./target/release/mtproxy-rs --genkey
```

## Client Connection

Your connection URL:

```
tg://proxy?server=YOUR_SERVER_IP&port=443&secret=YOUR_SECRET
```

Replace YOUR_SERVER_IP with your actual server IP and YOUR_SECRET with your generated secret.

## Common Options

```bash
mtproxy-rs [OPTIONS]

Key options:
  -H, --port <PORT>              Port to listen for MTProto connections (can be specified multiple times, default: 443, can also be set via env PORT)
  -p, --stats-port <PORT>        Stats port (default: 8888)
  -S, --secret <SECRET>          16-byte secret in hex
  -M, --slaves <NUM>             Worker processes (default: 1)
  -u, --user <USER>              Run as user (for security)
  --stats-token <TOKEN>          Bearer token for stats endpoint authentication
  --http-stats                   Enable HTTP stats server
  --genkey                       Generate a random secret key
```

## Security Best Practices

### 1. Authentication Protection
The proxy automatically implements rate limiting to prevent brute-force attacks:
- Max 5 failed authentication attempts per IP
- 5-minute block duration after exceeding limit
- Automatic cleanup of expired blocks

### 2. Stats Endpoint Security
**Always** protect your stats endpoint in production:

```bash
# Generate a secure token
STATS_TOKEN=$(openssl rand -hex 32)

# Run with authentication
./mtproxy-rs -S $SECRET --http-stats --stats-token $STATS_TOKEN

# Access stats with authentication
curl -H "Authorization: Bearer $STATS_TOKEN" http://localhost:8888/stats
```

Environment variable also supported:
```bash
export STATS_TOKEN="your-secure-token-here"
./mtproxy-rs -S $SECRET --http-stats
```

### 3. Network Security
- Bind stats port (8888) only to localhost/internal network
- Use firewall rules to restrict access
- Run as non-root user with `--user` option
- Enable connection limits via configuration

### 4. Configuration Hardening
Create a config file with security settings:

```conf
# proxy-config.conf
default 2
proxy_for 2 149.154.167.51:443
max_global_connections 500
max_connections_per_ip 50
read_timeout 180
cleanup_interval 30
```

### 5. Monitoring & Alerting
Monitor these metrics for security anomalies:
- `authentication_failures` - Spike indicates attack
- `connection_errors` - Network issues or attacks
- Active connections per IP

## Monitoring

### Endpoints
- **Stats**: `http://localhost:8888/stats` - JSON statistics (authentication required)
- **Health**: `http://localhost:8888/health` - Health check endpoint (public)
- **Prometheus**: `http://localhost:8888/prometheus` - Prometheus metrics (authentication required)
- **Root**: `http://localhost:8888/` - API documentation (public)

### Key Metrics
```bash
# With authentication
curl -H "Authorization: Bearer $STATS_TOKEN" http://localhost:8888/stats | jq

{
  "uptime_seconds": 3600,
  "total_connections": 1234,
  "active_connections": 42,
  "bytes_forwarded": 5368709120,
  "authentication_failures": 15,
  "network_rx_bytes": 1073741824,
  "network_tx_bytes": 2147483648,
  "memory_usage_bytes": 52428800
}
```

### Prometheus Integration
```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'mtproxy'
    static_configs:
      - targets: ['localhost:8888']
    metrics_path: '/prometheus'
    bearer_token: 'your-stats-token'
```

## Production Setup

### Systemd Service

```bash
# Create user
sudo useradd -r -s /bin/false mtproxy

# Create service file
sudo tee /etc/systemd/system/mtproxy-rs.service << EOF
[Unit]
Description=MTProxy-RS
After=network.target

[Service]
Type=simple
User=mtproxy
ExecStart=/usr/local/bin/mtproxy-rs -u mtproxy -p 8888 -H 443 -S YOUR_SECRET -M 1
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Enable & start
sudo systemctl enable --now mtproxy-rs
```

## Configuration

Download Telegram configuration files:

```bash
# Download config files
curl -s https://core.telegram.org/getProxyConfig > proxy-multi.conf
curl -s https://core.telegram.org/getProxySecret > proxy-secret

# Run with config files
./mtproxy-rs -u nobody -p 8888 -H 443 -S $SECRET --aes-pwd proxy-secret proxy-multi.conf -M 1
```

## License

MIT License - see [LICENSE](LICENSE) file.