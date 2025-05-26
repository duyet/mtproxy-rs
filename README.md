# mtproxy-rs

A high-performance Telegram MTProxy implementation in Rust.

[![Rust CI](https://github.com/duyet/mtproxy-rs/actions/workflows/rust-ci.yml/badge.svg)](https://github.com/duyet/mtproxy-rs/actions/workflows/rust-ci.yml)
[![Cross Platform Build](https://github.com/duyet/mtproxy-rs/actions/workflows/cross-platform-build.yml/badge.svg)](https://github.com/duyet/mtproxy-rs/actions/workflows/cross-platform-build.yml)
[![Docker Build & Publish](https://github.com/duyet/mtproxy-rs/actions/workflows/docker-build.yml/badge.svg)](https://github.com/duyet/mtproxy-rs/actions/workflows/docker-build.yml)

## Features

- Memory Safe - Written in Rust
- Docker Support
- HTTP stats API
- Compatible with original MTProxy
- CI/CD with GitHub Actions
- Cross-platform builds

## Quick Start

### Docker (Recommended)

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

# Or with docker-compose
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
  -H, --http-ports <PORTS>    Proxy ports (default: 443)
  -p, --stats-port <PORT>     Stats port (default: 8888)
  -S, --secret <SECRET>       16-byte secret in hex
  -M, --slaves <NUM>          Worker processes (default: 1)
  -u, --user <USER>           Run as user (for security)
  --genkey                    Generate a random secret key
```

## Monitoring

- Stats: `http://localhost:8888/stats`
- Health: `http://localhost:8888/health`

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

### Docker Production

```yaml
version: '3.8'
services:
  mtproxy-rs:
    image: ghcr.io/duyet/mtproxy-rs:latest
    restart: unless-stopped
    ports:
      - "443:443"
    environment:
      - RUST_LOG=warn
      - EXTRA_ARGS=-S YOUR_SECRET -M 4
    deploy:
      resources:
        limits:
          memory: 512M
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

## CI/CD

This project uses GitHub Actions for continuous integration and delivery:

1. **Rust CI**: Runs tests and code quality checks
2. **Cross-Platform Build**: Builds binaries for multiple platforms (Linux x86_64/ARM64, macOS x86_64/ARM64)
3. **Docker Build & Publish**: Builds multi-architecture Docker images and pushes them to GitHub Container Registry

Releases are automatically created when tags starting with `v` are pushed to the repository.

## License

MIT License - see [LICENSE](LICENSE) file.