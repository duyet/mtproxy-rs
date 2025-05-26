use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::Path;
use tokio::fs;
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxySecret {
    pub data: [u8; 16],
    pub tag: Option<[u8; 16]>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelegramServer {
    pub id: i32,
    pub ip: IpAddr,
    pub port: u16,
    pub secret: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    pub id: i32,
    pub servers: Vec<TelegramServer>,
    pub default: bool,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub clusters: Vec<ClusterConfig>,
    pub default_cluster_id: i32,
    #[allow(dead_code)]
    pub timeout: f64,
    #[allow(dead_code)]
    pub min_connections: u32,
    #[allow(dead_code)]
    pub max_connections: u32,
}

impl Config {
    pub async fn load(config_path: &Path) -> Result<Self> {
        info!("Loading configuration from: {}", config_path.display());

        // Read the configuration file
        let config_content = fs::read_to_string(config_path)
            .await
            .with_context(|| format!("Failed to read config file: {}", config_path.display()))?;

        Self::parse_config(&config_content)
    }

    /// Load AES secret from file
    pub async fn load_aes_secret(aes_pwd_file: &Path) -> Result<Vec<u8>> {
        info!("Loading AES secret from: {}", aes_pwd_file.display());
        fs::read(aes_pwd_file).await.with_context(|| {
            format!(
                "Failed to read AES password file: {}",
                aes_pwd_file.display()
            )
        })
    }

    pub fn parse_config(content: &str) -> Result<Self> {
        let mut clusters: Vec<ClusterConfig> = Vec::new();
        let mut default_cluster_id = -1;
        let mut timeout = 0.3;
        let mut min_connections = 1;
        let mut max_connections = 10;

        for line in content.lines() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            info!("Parsing config line: '{}'", line);

            // Remove trailing semicolon if present
            let line = line.trim_end_matches(';');
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            match parts[0] {
                "proxy-secret" => {
                    // Legacy support for proxy-secret in config file
                    debug!("Found proxy-secret in config (use --aes-pwd for binary secrets)");
                }
                "default" => {
                    if parts.len() >= 2 {
                        default_cluster_id = parts[1]
                            .parse::<i32>()
                            .context("Invalid default cluster ID")?;
                        info!("Set default cluster ID: {}", default_cluster_id);
                    }
                }
                "timeout" => {
                    if parts.len() >= 2 {
                        let timeout_ms =
                            parts[1].parse::<i32>().context("Invalid timeout value")?;
                        if !(10..=30000).contains(&timeout_ms) {
                            anyhow::bail!("Invalid timeout: must be between 10 and 30000 ms");
                        }
                        timeout = timeout_ms as f64 / 1000.0;
                        debug!("Set timeout: {} seconds", timeout);
                    }
                }
                "min_connections" => {
                    if parts.len() >= 2 {
                        min_connections = parts[1]
                            .parse::<u32>()
                            .context("Invalid min_connections value")?;
                        debug!("Set min_connections: {}", min_connections);
                    }
                }
                "max_connections" => {
                    if parts.len() >= 2 {
                        max_connections = parts[1]
                            .parse::<u32>()
                            .context("Invalid max_connections value")?;
                        debug!("Set max_connections: {}", max_connections);
                    }
                }
                "proxy_for" => {
                    if parts.len() >= 3 {
                        // Parse: proxy_for <dc_id> <ip>:<port>
                        let dc_id = parts[1]
                            .parse::<i32>()
                            .context("Invalid DC ID in proxy_for")?;

                        // Parse IP:PORT
                        let addr_port = parts[2];
                        if let Some(colon_pos) = addr_port.find(':') {
                            let ip_str = &addr_port[..colon_pos];
                            let port_str = &addr_port[colon_pos + 1..];

                            let ip = ip_str
                                .parse::<IpAddr>()
                                .with_context(|| format!("Invalid IP address: {}", ip_str))?;
                            let port = port_str
                                .parse::<u16>()
                                .with_context(|| format!("Invalid port: {}", port_str))?;

                            // Find or create cluster for this DC
                            let cluster_index = clusters.iter().position(|c| c.id == dc_id);
                            let cluster = if let Some(index) = cluster_index {
                                &mut clusters[index]
                            } else {
                                clusters.push(ClusterConfig {
                                    id: dc_id,
                                    servers: Vec::new(),
                                    default: false,
                                });
                                clusters.last_mut().unwrap()
                            };

                            {
                                let server = TelegramServer {
                                    id: cluster.servers.len() as i32,
                                    ip,
                                    port,
                                    secret: Vec::new(), // No secrets in proxy_for format
                                };

                                info!("Added server {}:{} to cluster {}", ip, port, dc_id);
                                cluster.servers.push(server);
                            }
                        } else {
                            anyhow::bail!("Invalid address format in proxy_for: expected IP:PORT");
                        }
                    }
                }
                _ => {
                    // Try to parse as server entry for proxy-multi: IP:PORT SECRET
                    if !clusters.is_empty() {
                        if let Some(colon_pos) = parts[0].find(':') {
                            let ip_str = &parts[0][..colon_pos];
                            let port_str = &parts[0][colon_pos + 1..];

                            if let (Ok(ip), Ok(port)) =
                                (ip_str.parse::<IpAddr>(), port_str.parse::<u16>())
                            {
                                if parts.len() >= 2 {
                                    let secret = hex::decode(parts[1])
                                        .context("Invalid server secret hex format")?;

                                    if let Some(cluster) = clusters.last_mut() {
                                        let server = TelegramServer {
                                            id: cluster.servers.len() as i32,
                                            ip,
                                            port,
                                            secret,
                                        };

                                        debug!(
                                            "Added server {}:{} to cluster {}",
                                            ip, port, cluster.id
                                        );
                                        cluster.servers.push(server);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if clusters.is_empty() {
            anyhow::bail!("No clusters found in configuration");
        }

        // Set default cluster
        if default_cluster_id != -1 {
            if let Some(cluster) = clusters.iter_mut().find(|c| c.id == default_cluster_id) {
                cluster.default = true;
                debug!("Marked cluster {} as default", default_cluster_id);
            }
        } else {
            // If no default specified, use the first cluster
            if let Some(first_cluster) = clusters.first_mut() {
                default_cluster_id = first_cluster.id;
                first_cluster.default = true;
                warn!(
                    "No default cluster specified, using cluster {}",
                    default_cluster_id
                );
            }
        }

        // Validate that we have at least one server in some cluster
        let total_servers: usize = clusters.iter().map(|c| c.servers.len()).sum();
        if total_servers == 0 {
            anyhow::bail!("No proxy servers found in configuration");
        }

        Ok(Config {
            clusters,
            default_cluster_id,
            timeout,
            min_connections,
            max_connections,
        })
    }

    pub fn get_cluster(&self, id: i32) -> Option<&ClusterConfig> {
        self.clusters.iter().find(|c| c.id == id)
    }

    pub fn get_default_cluster(&self) -> Option<&ClusterConfig> {
        self.get_cluster(self.default_cluster_id)
    }

    #[allow(dead_code)]
    pub fn get_server_by_dc(&self, dc_id: i32) -> Option<&TelegramServer> {
        for cluster in &self.clusters {
            if cluster.id == dc_id {
                return cluster.servers.first();
            }
        }
        None
    }

    /// Download the latest configuration from Telegram
    pub async fn download_latest() -> Result<String> {
        let url = "https://core.telegram.org/getProxyConfig";
        info!("Downloading latest Telegram configuration from {}", url);

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let response = client
            .get("https://core.telegram.org/getProxyConfig")
            .send()
            .await
            .context("Failed to download proxy config")?;

        if !response.status().is_success() {
            anyhow::bail!("Failed to download config: HTTP {}", response.status());
        }

        let config_text = response
            .text()
            .await
            .context("Failed to read config response")?;

        Ok(config_text)
    }

    /// Download the proxy secret from Telegram
    pub async fn download_proxy_secret() -> Result<Vec<u8>> {
        info!("Downloading latest proxy secret");

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let response = client
            .get("https://core.telegram.org/getProxySecret")
            .send()
            .await
            .context("Failed to download proxy secret")?;

        if !response.status().is_success() {
            anyhow::bail!("Failed to download secret: HTTP {}", response.status());
        }

        let secret_data = response
            .bytes()
            .await
            .context("Failed to read secret response")?;

        Ok(secret_data.to_vec())
    }
}

// Add reqwest dependency
impl Config {
    /// Auto-update configuration from Telegram servers
    #[allow(dead_code)]
    pub async fn auto_update(config_path: &Path) -> Result<()> {
        info!("Auto-updating configuration");

        // Download latest config
        let config_content = Self::download_latest().await?;

        // Write to file
        fs::write(config_path, config_content)
            .await
            .context("Failed to write updated config")?;

        info!("Configuration updated successfully");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    use std::io::Write;

    #[tokio::test]
    async fn test_config_parsing_proxy_for() {
        let config_content = r#"
# Proxy configuration using proxy_for format (like C version)
default 2;
proxy_for 1 149.154.175.50:8888;
proxy_for -1 149.154.175.50:8888;
proxy_for 2 149.154.161.144:8888;
proxy_for -2 149.154.161.144:8888;
proxy_for 3 149.154.175.100:8888;
proxy_for -3 149.154.175.100:8888;
"#;

        let config = Config::parse_config(config_content).unwrap();

        assert_eq!(config.clusters.len(), 6); // 1, -1, 2, -2, 3, -3
        assert_eq!(config.default_cluster_id, 2);

        let default_cluster = config.get_default_cluster().unwrap();
        assert_eq!(default_cluster.servers.len(), 1);
        assert_eq!(default_cluster.servers[0].port, 8888);
        assert_eq!(default_cluster.servers[0].ip.to_string(), "149.154.161.144");
    }

    #[tokio::test]
    async fn test_config_file_loading() {
        let config_content = r#"
# Test configuration
default 1;
proxy_for 1 149.154.175.50:8888;
timeout 5000;
min_connections 2;
max_connections 20;
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(config_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let config = Config::load(temp_file.path()).await.unwrap();
        assert_eq!(config.clusters.len(), 1);
        assert_eq!(config.default_cluster_id, 1);
        assert_eq!(config.timeout, 5.0);
        assert_eq!(config.min_connections, 2);
        assert_eq!(config.max_connections, 20);
    }

    #[tokio::test]
    async fn test_aes_secret_loading() {
        let secret_data = b"deadbeefcafebabe";

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(secret_data).unwrap();
        temp_file.flush().unwrap();

        let loaded_secret = Config::load_aes_secret(temp_file.path()).await.unwrap();
        assert_eq!(loaded_secret, secret_data.to_vec());
    }
}
