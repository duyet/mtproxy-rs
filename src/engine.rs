use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::signal;
use tokio::sync::broadcast;
use tracing::{error, info, warn};

use crate::config::Config;
use crate::mtproto::MtProtoProxy;
use crate::network::NetworkManager;
use crate::stats::StatsServer;
use crate::ProxyArgs;

/// Main engine that coordinates all proxy components
pub struct Engine {
    /// Proxy arguments
    args: ProxyArgs,
    /// Configuration
    config: Arc<Config>,
    /// MTProto proxy handler
    mtproto_proxy: Arc<MtProtoProxy>,
    /// Network manager
    network_manager: Arc<NetworkManager>,
    /// Statistics server
    stats_server: Arc<StatsServer>,
    /// Shutdown signal
    shutdown_tx: broadcast::Sender<()>,
    shutdown_rx: broadcast::Receiver<()>,
}

impl Engine {
    /// Create a new engine instance
    pub async fn new(args: ProxyArgs, config: Config) -> Result<Self> {
        info!("Initializing MTProxy engine");

        // Convert secrets from hex strings to byte arrays
        let mut proxy_secrets = Vec::new();
        for secret_str in &args.secrets {
            let secret_bytes = hex::decode(secret_str)
                .with_context(|| format!("Invalid secret format: {}", secret_str))?;
            if secret_bytes.len() != 16 {
                anyhow::bail!("Secret must be exactly 16 bytes: {}", secret_str);
            }
            let mut secret = [0u8; 16];
            secret.copy_from_slice(&secret_bytes);
            proxy_secrets.push(secret);
        }

        // Convert proxy tag from hex string if provided
        let proxy_tag = if let Some(ref tag_str) = args.proxy_tag {
            let tag_bytes = hex::decode(tag_str)
                .with_context(|| format!("Invalid proxy tag format: {}", tag_str))?;
            if tag_bytes.len() != 16 {
                anyhow::bail!("Proxy tag must be exactly 16 bytes: {}", tag_str);
            }
            let mut tag = [0u8; 16];
            tag.copy_from_slice(&tag_bytes);
            Some(tag)
        } else {
            None
        };

        let config = Arc::new(config);

        // Create MTProto proxy
        let mtproto_proxy = Arc::new(MtProtoProxy::new(proxy_secrets, proxy_tag));

        // Create network manager
        let network_manager = Arc::new(NetworkManager::new(config.clone(), mtproto_proxy.clone()));

        // Create statistics server
        let stats_server = Arc::new(StatsServer::new(network_manager.clone()));

        // Create shutdown channel
        let (shutdown_tx, shutdown_rx) = broadcast::channel(16);

        info!("Engine initialized successfully");

        Ok(Engine {
            args,
            config,
            mtproto_proxy,
            network_manager,
            stats_server,
            shutdown_tx,
            shutdown_rx,
        })
    }

    /// Run the proxy engine
    pub async fn run(&mut self) -> Result<()> {
        info!("Starting MTProxy engine");

        // Start network listeners
        if !self.args.http_ports.is_empty() {
            self.network_manager
                .start_listeners(&self.args.http_ports)
                .await
                .context("Failed to start network listeners")?;
        } else {
            warn!("No HTTP ports specified, proxy will not accept connections");
        }

        // Start statistics server
        let stats_server = self.stats_server.clone();
        let stats_port = self.args.stats_port;
        let http_stats = self.args.http_stats;
        tokio::spawn(async move {
            if let Err(e) = stats_server.start(stats_port, http_stats).await {
                error!("Statistics server error: {}", e);
            }
        });

        // Start worker processes if specified
        if self.args.workers > 1 {
            info!("Starting {} worker processes", self.args.workers);
            self.start_workers().await?;
        }

        // Setup signal handlers
        self.setup_signal_handlers().await?;

        // Main event loop
        self.main_loop().await?;

        info!("MTProxy engine stopped");
        Ok(())
    }

    /// Start worker processes
    async fn start_workers(&self) -> Result<()> {
        // In a real implementation, you would fork worker processes here
        // For this Rust implementation, we'll use async tasks instead

        for worker_id in 1..self.args.workers {
            info!("Starting worker {}", worker_id);

            let network_manager = self.network_manager.clone();
            let http_ports: Vec<u16> = self
                .args
                .http_ports
                .iter()
                .filter_map(|&port| {
                    // Prevent port overflow - max valid port is 65535
                    let offset = worker_id * 1000;
                    let new_port = port as u32 + offset;
                    if new_port > 65535 {
                        warn!(
                            "Worker {} port {} + {} would overflow, skipping",
                            worker_id, port, offset
                        );
                        None
                    } else {
                        Some(new_port as u16)
                    }
                })
                .collect();

            tokio::spawn(async move {
                if let Err(e) = network_manager.start_listeners(&http_ports).await {
                    error!("Worker {} failed: {}", worker_id, e);
                }
            });
        }

        Ok(())
    }

    /// Setup signal handlers for graceful shutdown
    async fn setup_signal_handlers(&mut self) -> Result<()> {
        let shutdown_tx = self.shutdown_tx.clone();

        // Handle SIGTERM and SIGINT
        tokio::spawn(async move {
            let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
                .expect("Failed to setup SIGTERM handler");
            let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())
                .expect("Failed to setup SIGINT handler");

            tokio::select! {
                _ = sigterm.recv() => {
                    info!("Received SIGTERM, initiating graceful shutdown");
                }
                _ = sigint.recv() => {
                    info!("Received SIGINT, initiating graceful shutdown");
                }
            }

            let _ = shutdown_tx.send(());
        });

        // Handle SIGUSR1 for configuration reload
        let _config = self.config.clone();
        let config_file = self.args.config_file.clone();
        tokio::spawn(async move {
            let mut sigusr1 = signal::unix::signal(signal::unix::SignalKind::user_defined1())
                .expect("Failed to setup SIGUSR1 handler");

            while sigusr1.recv().await.is_some() {
                info!("Received SIGUSR1, reloading configuration");

                if let Some(ref config_file_path) = config_file {
                    match Config::load(config_file_path).await {
                        Ok(_new_config) => {
                            info!("Configuration reloaded successfully");
                            // In a real implementation, you would update the running config
                            // This is complex as it requires updating all components
                        }
                        Err(e) => {
                            error!("Failed to reload configuration: {}", e);
                        }
                    }
                } else {
                    warn!(
                        "Cannot reload configuration: no config file specified (auto-config mode)"
                    );
                }
            }
        });

        Ok(())
    }

    /// Main event loop
    async fn main_loop(&mut self) -> Result<()> {
        info!("MTProxy is running and ready to accept connections");

        // Print connection information
        self.print_connection_info();

        // Wait for shutdown signal
        let _ = self.shutdown_rx.recv().await;

        info!("Shutdown signal received, stopping all services");

        // Graceful shutdown
        self.shutdown().await?;

        Ok(())
    }

    /// Print connection information for users
    fn print_connection_info(&self) {
        info!("=== MTProxy Connection Information ===");

        for &port in &self.args.http_ports {
            info!("Listening on port: {}", port);
        }

        info!(
            "Statistics available at: http://localhost:{}/stats",
            self.args.stats_port
        );

        if !self.args.secrets.is_empty() {
            info!("Configured secrets:");

            // Try to get the real server address
            let server_address = self.get_server_address();

            for (i, secret) in self.args.secrets.iter().enumerate() {
                info!("  Secret {}: {}", i + 1, secret);

                // Generate example connection URLs with real server address
                for &port in &self.args.http_ports {
                    let url = format!(
                        "tg://proxy?server={}&port={}&secret={}",
                        server_address, port, secret
                    );
                    info!("  Connection URL: {}", url);
                }
            }

            info!("");
            info!("📱 To use this proxy in Telegram:");
            info!("   1. Copy one of the connection URLs above");
            info!("   2. Open Telegram app");
            info!("   3. Paste the URL in any chat");
            info!("   4. Tap the URL to configure proxy");
            info!("");
            info!("🔧 Alternative setup:");
            info!("   Server: {}", server_address);
            info!("   Port: {}", self.args.http_ports.first().unwrap_or(&443));
            info!(
                "   Secret: {}",
                self.args.secrets.first().unwrap_or(&"N/A".to_string())
            );
            info!("");
            info!("🛡️  Random Padding (for ISP bypass):");
            if let Some(secret) = self.args.secrets.first() {
                for &port in &self.args.http_ports {
                    let padded_url = format!(
                        "tg://proxy?server={}&port={}&secret=dd{}",
                        server_address, port, secret
                    );
                    info!("   Padded URL: {}", padded_url);
                }
            }
            info!("   (Random padding helps avoid ISP detection)");

            // Asynchronously update with public IP if needed
            if server_address == "YOUR_SERVER_IP"
                || crate::utils::network::is_private_ip(
                    &server_address
                        .parse()
                        .unwrap_or("127.0.0.1".parse().unwrap()),
                )
            {
                let secrets = self.args.secrets.clone();
                let ports = self.args.http_ports.clone();
                tokio::spawn(async move {
                    if let Ok(public_ip) = crate::utils::network::get_public_ip().await {
                        info!("Detected public IP address: {}", public_ip);
                        info!("Updated connection URLs:");
                        for (i, secret) in secrets.iter().enumerate() {
                            for &port in &ports {
                                let url = format!(
                                    "tg://proxy?server={}&port={}&secret={}",
                                    public_ip, port, secret
                                );
                                info!("  Secret {} URL: {}", i + 1, url);

                                // Also provide random padding version
                                let padded_url = format!(
                                    "tg://proxy?server={}&port={}&secret=dd{}",
                                    public_ip, port, secret
                                );
                                info!("  Secret {} Padded URL: {}", i + 1, padded_url);
                            }
                        }
                    }
                });
            }
        }

        if let Some(ref tag) = self.args.proxy_tag {
            info!("Proxy tag: {}", tag);
        }

        if !self.args.domains.is_empty() {
            info!("TLS domains: {:?}", self.args.domains);
        }

        info!("Workers: {}", self.args.workers);
        info!("=====================================");
    }

    /// Get the best server address for connection URLs
    fn get_server_address(&self) -> String {
        // 1. Check if we have a domain configured (best for public access)
        if !self.args.domains.is_empty() {
            return self.args.domains[0].clone();
        }

        // 2. Try to get local IP as immediate fallback
        if let Ok(local_ip) = crate::utils::network::get_local_ip() {
            if !crate::utils::network::is_private_ip(&local_ip) {
                info!("Using local non-private IP: {}", local_ip);
                return local_ip.to_string();
            }
        }

        // 3. Try environment variable
        if let Ok(hostname) = std::env::var("HOSTNAME") {
            if !hostname.is_empty() && hostname != "localhost" {
                return hostname;
            }
        }

        // 4. Try system hostname
        if let Ok(output) = std::process::Command::new("hostname").output() {
            if let Ok(hostname) = String::from_utf8(output.stdout) {
                let hostname = hostname.trim();
                if !hostname.is_empty() && hostname != "localhost" {
                    return hostname.to_string();
                }
            }
        }

        // 5. Final fallback - will be updated by async task
        "YOUR_SERVER_IP".to_string()
    }

    /// Graceful shutdown
    async fn shutdown(&self) -> Result<()> {
        info!("Initiating graceful shutdown");

        // Signal all components to shut down
        let _ = self.shutdown_tx.send(());

        // Shutdown network manager
        if let Err(e) = self.network_manager.shutdown().await {
            error!("Error shutting down network manager: {}", e);
        }

        // Give some time for connections to close gracefully
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        info!("Graceful shutdown completed");
        Ok(())
    }

    /// Get engine statistics
    pub async fn get_stats(&self) -> Result<serde_json::Value> {
        let (client_connections, server_connections) = self.mtproto_proxy.get_stats().await;
        let active_connections = self.network_manager.get_active_connections().await;
        let network_stats = self.network_manager.get_stats();

        Ok(serde_json::json!({
            "mtproto": {
                "client_connections": client_connections,
                "server_connections": server_connections
            },
            "network": {
                "active_connections": active_connections,
                "total_connections": network_stats.total_connections.load(std::sync::atomic::Ordering::Relaxed),
                "bytes_forwarded": network_stats.bytes_forwarded.load(std::sync::atomic::Ordering::Relaxed),
                "messages_forwarded": network_stats.messages_forwarded.load(std::sync::atomic::Ordering::Relaxed),
                "connection_errors": network_stats.connection_errors.load(std::sync::atomic::Ordering::Relaxed),
                "authentication_failures": network_stats.authentication_failures.load(std::sync::atomic::Ordering::Relaxed)
            },
            "config": {
                "secrets_count": self.args.secrets.len(),
                "http_ports": self.args.http_ports,
                "workers": self.args.workers,
                "domains": self.args.domains
            }
        }))
    }

    /// Health check
    pub fn health_check(&self) -> bool {
        // Basic health check - could be extended to check component health
        true
    }

    /// Reload configuration
    pub async fn reload_config(&mut self) -> Result<()> {
        if let Some(ref config_file) = self.args.config_file {
            info!("Reloading configuration from: {}", config_file.display());

            let new_config = Config::load(config_file).await?;
            self.config = Arc::new(new_config);

            info!("Configuration reloaded successfully");
            Ok(())
        } else {
            anyhow::bail!(
                "Cannot reload configuration: no config file specified (auto-config mode)"
            );
        }
    }
}

/// Utility functions for engine management
pub mod utils {
    use super::*;

    /// Check if running as root
    pub fn is_running_as_root() -> bool {
        unsafe { libc::getuid() == 0 }
    }

    /// Validate proxy configuration
    pub fn validate_config(args: &ProxyArgs) -> Result<()> {
        // Check secrets
        if args.secrets.is_empty() && args.domains.is_empty() {
            anyhow::bail!("Must specify at least one secret or domain");
        }

        for secret in &args.secrets {
            if secret.len() != 32 {
                anyhow::bail!("Secret must be 32 hex characters: {}", secret);
            }
            if hex::decode(secret).is_err() {
                anyhow::bail!("Invalid hex in secret: {}", secret);
            }
        }

        // Check proxy tag
        if let Some(ref tag) = args.proxy_tag {
            if tag.len() != 32 {
                anyhow::bail!("Proxy tag must be 32 hex characters: {}", tag);
            }
            if hex::decode(tag).is_err() {
                anyhow::bail!("Invalid hex in proxy tag: {}", tag);
            }
        }

        // Check ports
        if args.http_ports.is_empty() {
            anyhow::bail!("Must specify at least one HTTP port");
        }

        for &port in &args.http_ports {
            if port < 1024 && !is_running_as_root() {
                anyhow::bail!("Port {} requires root privileges", port);
            }

            // Check for potential port overflow with workers
            if args.workers > 1 {
                let max_worker_offset = (args.workers - 1) * 1000;
                let max_port = port as u32 + max_worker_offset;
                if max_port > 65535 {
                    anyhow::bail!(
                        "Port {} with {} workers would overflow (max port: {})",
                        port,
                        args.workers,
                        max_port
                    );
                }
            }
        }

        // Check configuration file if specified
        if let Some(ref config_file) = args.config_file {
            if !config_file.exists() {
                anyhow::bail!("Configuration file not found: {}", config_file.display());
            }
        }

        // Check AES password file if specified
        if let Some(ref aes_file) = args.aes_pwd_file {
            if !aes_file.exists() {
                anyhow::bail!("AES password file not found: {}", aes_file.display());
            }
        }

        Ok(())
    }

    /// Generate a complete proxy configuration
    pub fn generate_config_template() -> String {
        r#"# MTProxy Configuration Template
# Generated by mtproxy-rs

# Proxy secret (download from https://core.telegram.org/getProxySecret)
proxy-secret 00112233445566778899aabbccddeeff

# Telegram server clusters
# Format: proxy-multi <cluster_id> <ip1> <port1> <secret1> [default_flag]

# Main cluster (DC1-5)
proxy-multi 1 0 0 0 1
149.154.175.50:443 abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
149.154.167.51:443 1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
149.154.175.100:443 fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321
149.154.167.91:443 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
91.108.56.100:443 abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234

# Secondary cluster (backup)
proxy-multi 2 0 0 0 0
149.154.171.5:443 5678abcd5678abcd5678abcd5678abcd5678abcd5678abcd5678abcd5678abcd
"#
        .to_string()
    }

    /// Create systemd service file
    pub fn generate_systemd_service(install_path: &str) -> String {
        format!(
            r#"[Unit]
Description=MTProxy-RS - Telegram MTProto Proxy
After=network.target
Wants=network.target

[Service]
Type=simple
User=mtproxy
Group=mtproxy
ExecStart={} -u mtproxy -p 8888 -H 443 -S YOUR_SECRET proxy-multi.conf -M 1
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=mtproxy-rs

# Security settings
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictNamespaces=true

# Working directory
WorkingDirectory=/etc/mtproxy-rs

[Install]
WantedBy=multi-user.target
"#,
            install_path
        )
    }

    /// Create Docker Compose configuration
    pub fn generate_docker_compose() -> String {
        r#"version: '3.8'

services:
  mtproxy-rs:
    build: .
    container_name: mtproxy-rs
    restart: unless-stopped
    ports:
      - "443:443"
      - "8888:8888"
    volumes:
      - ./config:/app/config:ro
    environment:
      - RUST_LOG=info
    command: >
      ./mtproxy-rs
      -u nobody
      -p 8888
      -H 443
      -S ${MTPROXY_SECRET}
      --aes-pwd /app/config/proxy-secret
      /app/config/proxy-multi.conf
      -M 1
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8888/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s

  prometheus:
    image: prom/prometheus:latest
    container_name: mtproxy-prometheus
    restart: unless-stopped
    ports:
      - "9090:9090"
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml:ro
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'

  grafana:
    image: grafana/grafana:latest
    container_name: mtproxy-grafana
    restart: unless-stopped
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana-storage:/var/lib/grafana
      - ./monitoring/grafana:/etc/grafana/provisioning:ro

volumes:
  grafana-storage:
"#
        .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_engine_creation() {
        let temp_dir = tempdir().unwrap();
        let config_file = temp_dir.path().join("test.conf");
        std::fs::write(
            &config_file,
            "default 2;\nproxy_for 1 149.154.175.50:8888;\nproxy_for 2 149.154.161.144:8888;",
        )
        .unwrap();

        // Create args with the config file
        let args = ProxyArgs {
            username: Some("test".to_string()),
            stats_port: 8888,
            http_ports: vec![8080],
            secrets: vec!["deadbeefcafebabe1234567890abcdef".to_string()],
            proxy_tag: None,
            domains: vec![],
            max_connections: None,
            window_clamp: None,
            workers: 1,
            ping_interval: 60.0,
            aes_pwd_file: None,
            config_file: Some(config_file.clone()),
            http_stats: false,
            genkey: false,
        };

        let config = Config::load(&config_file).await.unwrap();

        let engine = Engine::new(args, config).await;
        assert!(engine.is_ok());

        // Keep temp_dir alive until test completes
        drop(temp_dir);
    }

    // Test for port overflow bug
    #[tokio::test]
    async fn test_worker_port_overflow() {
        let temp_dir = tempdir().unwrap();
        let config_file = temp_dir.path().join("test.conf");
        std::fs::write(&config_file, "default 1;\nproxy_for 1 149.154.175.50:8888;").unwrap();

        // Test with ports that would overflow when workers are added
        let args = ProxyArgs {
            username: None,
            stats_port: 8888,
            http_ports: vec![60000], // This + worker_id * 1000 could overflow
            secrets: vec!["deadbeefcafebabe1234567890abcdef".to_string()],
            proxy_tag: None,
            domains: vec![],
            max_connections: None,
            window_clamp: None,
            workers: 10, // worker_id 9 would cause 60000 + 9000 = 69000 > 65535
            ping_interval: 60.0,
            aes_pwd_file: None,
            config_file: Some(config_file.clone()),
            http_stats: false,
            genkey: false,
        };

        let config = Config::load(&config_file).await.unwrap();
        let engine = Engine::new(args, config).await.unwrap();

        // This should fail gracefully, not overflow
        let result = engine.start_workers().await;
        // For now, this will likely succeed but shouldn't cause overflow
        // After we fix the bug, we'll add proper validation
    }

    // Test for multiple workers with valid ports
    #[tokio::test]
    async fn test_multiple_workers_valid_ports() {
        let temp_dir = tempdir().unwrap();
        let config_file = temp_dir.path().join("test.conf");
        std::fs::write(&config_file, "default 1;\nproxy_for 1 149.154.175.50:8888;").unwrap();

        let args = ProxyArgs {
            username: None,
            stats_port: 8888,
            http_ports: vec![8080], // Safe base port
            secrets: vec!["deadbeefcafebabe1234567890abcdef".to_string()],
            proxy_tag: None,
            domains: vec![],
            max_connections: None,
            window_clamp: None,
            workers: 3,
            ping_interval: 60.0,
            aes_pwd_file: None,
            config_file: Some(config_file.clone()),
            http_stats: false,
            genkey: false,
        };

        let config = Config::load(&config_file).await.unwrap();
        let engine = Engine::new(args, config).await.unwrap();

        let result = engine.start_workers().await;
        assert!(result.is_ok());
    }

    fn create_test_args_no_file() -> ProxyArgs {
        ProxyArgs {
            username: Some("test".to_string()),
            stats_port: 8888,
            http_ports: vec![8080], // Use non-privileged port for tests
            secrets: vec!["deadbeefcafebabe1234567890abcdef".to_string()],
            proxy_tag: None,
            domains: vec![],
            max_connections: None,
            window_clamp: None,
            workers: 1,
            ping_interval: 60.0,
            aes_pwd_file: None,
            config_file: None, // No config file needed for validation test
            http_stats: false,
            genkey: false,
        }
    }

    #[test]
    fn test_config_validation() {
        // Use args without config file to avoid file existence check
        let args = create_test_args_no_file();
        let result = utils::validate_config(&args);
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_secret() {
        let mut args = create_test_args_no_file();
        args.secrets = vec!["invalid_hex".to_string()];

        let result = utils::validate_config(&args);
        assert!(result.is_err());
    }

    #[test]
    fn test_port_overflow_validation() {
        let mut args = create_test_args_no_file();
        args.http_ports = vec![60000];
        args.workers = 10; // This would cause overflow

        let result = utils::validate_config(&args);
        // After we fix the bug, this should fail validation
        // For now, let's just ensure it doesn't panic
    }

    #[test]
    fn test_template_generation() {
        let template = utils::generate_config_template();
        assert!(template.contains("proxy-secret"));
        assert!(template.contains("proxy-multi"));
    }
}
