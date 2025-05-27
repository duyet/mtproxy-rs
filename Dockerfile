# Use the official Rust image as the base
FROM rust:1.87-slim AS builder

# Install dependencies for building
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libc6-dev \
    curl \
    perl \
    make \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /app

# Copy dependency files
COPY Cargo.toml ./

# Create a dummy main file to build dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies (this layer will be cached if dependencies don't change)
RUN cargo build --release && rm -rf src

# Copy the source code
COPY src ./src

# Build the application with optimizations
RUN cargo build --release

# Use a minimal runtime image
FROM debian:bookworm-slim

# Install runtime dependencies for IP detection and networking
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    net-tools \
    iputils-ping \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN groupadd -r mtproxy && useradd -r -g mtproxy -d /app mtproxy

# Create app directory and set permissions
RUN mkdir -p /app/config /app/logs && \
    chown -R mtproxy:mtproxy /app

# Copy the binary from the builder stage
COPY --from=builder /app/target/release/mtproxy-rs /usr/local/bin/mtproxy-rs

# Make the binary executable
RUN chmod +x /usr/local/bin/mtproxy-rs

# Switch to app directory
WORKDIR /app

# Copy startup script
COPY --chown=mtproxy:mtproxy docker-entrypoint.sh /docker-entrypoint.sh

# Switch to non-root user
USER mtproxy

# Expose ports
EXPOSE 443 8888

# Add health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8888/health || exit 1

# Set environment variables with defaults
ENV RUST_LOG=info \
    STATS_PORT=8888 \
    PORT=443 \
    WORKERS=1

# Use the startup script as the default command
CMD ["/docker-entrypoint.sh"] 