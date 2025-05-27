// MTProxy-RS Library
//
// This file exposes the main modules for use in integration tests and
// potential future library usage.

pub mod config;
pub mod crypto;
pub mod engine;
pub mod jobs;
pub mod mtproto;
pub mod network;
pub mod stats;
pub mod utils;

// Re-export key types for easier access
pub use crate::config::Config;
pub use crate::engine::Engine;

// Re-export the ProxyArgs from main
#[derive(Debug)]
pub struct ProxyArgs {
    pub username: Option<String>,
    pub stats_port: u16,
    pub http_ports: Vec<u16>,
    pub secrets: Vec<String>,
    pub proxy_tag: Option<String>,
    pub domains: Vec<String>,
    pub max_connections: Option<u32>,
    pub window_clamp: Option<u32>,
    pub workers: u32,
    pub ping_interval: f64,
    pub aes_pwd_file: Option<std::path::PathBuf>,
    pub config_file: Option<std::path::PathBuf>,
    pub http_stats: bool,
    pub genkey: bool,
}
