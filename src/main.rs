use anyhow::{Context, Result};
use clap::{Arg, Command};
use nix::unistd::setuid;
use std::path::PathBuf;
use tokio::signal::unix;
use tracing::{info, warn};

mod config;
mod crypto;
mod engine;
mod jobs;
mod mtproto;
mod network;
mod stats;
mod utils;

use config::Config;
use engine::Engine;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_PING_INTERVAL: f64 = 60.0;

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
    pub aes_pwd_file: Option<PathBuf>,
    pub config_file: Option<PathBuf>,
    pub http_stats: bool,
    pub genkey: bool,
}

fn build_cli() -> Command {
    Command::new("mtproxy-rs")
        .version(VERSION)
        .about("High-performance MTProxy implementation in Rust")
        .arg(
            Arg::new("username")
                .short('u')
                .long("user")
                .value_name("USERNAME")
                .help("Username to run as (drops privileges)"),
        )
        .arg(
            Arg::new("stats_port")
                .short('p')
                .long("stats-port")
                .value_name("PORT")
                .default_value("8888")
                .help("Local statistics port")
                .value_parser(clap::value_parser!(u16).range(1..=65535)),
        )
        .arg(
            Arg::new("http_ports")
                .short('H')
                .long("http-ports")
                .value_name("PORT")
                .help("Client HTTP port (can be specified multiple times)")
                .action(clap::ArgAction::Append)
                .value_parser(clap::value_parser!(u16).range(1..=65535)),
        )
        .arg(
            Arg::new("secret")
                .short('S')
                .long("mtproto-secret")
                .value_name("SECRET")
                .help("16-byte secret in hex mode")
                .action(clap::ArgAction::Append),
        )
        .arg(
            Arg::new("proxy_tag")
                .short('P')
                .long("proxy-tag")
                .value_name("TAG")
                .help("16-byte proxy tag in hex mode"),
        )
        .arg(
            Arg::new("ad_tag")
                .long("ad-tag")
                .value_name("TAG")
                .help("16-byte advertising tag in hex mode (alias for proxy-tag)"),
        )
        .arg(
            Arg::new("domain")
                .short('D')
                .long("domain")
                .value_name("DOMAIN")
                .help("Allowed domain for TLS-transport mode")
                .action(clap::ArgAction::Append),
        )
        .arg(
            Arg::new("max_connections")
                .short('C')
                .long("max-special-connections")
                .value_name("NUM")
                .help("Maximum number of client connections per worker"),
        )
        .arg(
            Arg::new("window_clamp")
                .short('W')
                .long("window-clamp")
                .value_name("SIZE")
                .help("Window clamp for client TCP connections"),
        )
        .arg(
            Arg::new("workers")
                .short('M')
                .long("slaves")
                .value_name("NUM")
                .default_value("1")
                .help("Number of worker processes")
                .value_parser(clap::value_parser!(u32).range(1..=32)),
        )
        .arg(
            Arg::new("ping_interval")
                .short('T')
                .long("ping-interval")
                .value_name("SECONDS")
                .help("Ping interval for local TCP connections"),
        )
        .arg(
            Arg::new("aes_pwd_file")
                .long("aes-pwd")
                .value_name("FILE")
                .help("AES password file"),
        )
        .arg(
            Arg::new("http_stats")
                .long("http-stats")
                .action(clap::ArgAction::SetTrue)
                .help("Allow HTTP server to answer stats queries"),
        )
        .arg(
            Arg::new("ip")
                .long("ip")
                .value_name("ADDRESS")
                .help("Override external IP address detection"),
        )
        .arg(
            Arg::new("genkey")
                .long("genkey")
                .action(clap::ArgAction::SetTrue)
                .help("Generate a random secret key for MTProxy"),
        )
        .arg(
            Arg::new("config")
                .value_name("CONFIG_FILE")
                .help("Configuration file (auto-downloaded if not provided)")
                .required(false),
        )
}

fn parse_hex_secret(secret: &str) -> Result<[u8; 16]> {
    if secret.len() != 32 {
        anyhow::bail!("Secret must be exactly 32 hex characters");
    }

    let mut bytes = [0u8; 16];
    for (i, chunk) in secret.as_bytes().chunks(2).enumerate() {
        let hex_str = std::str::from_utf8(chunk)?;
        bytes[i] = u8::from_str_radix(hex_str, 16)
            .with_context(|| format!("Invalid hex character in secret: {}", hex_str))?;
    }

    Ok(bytes)
}

fn parse_args() -> Result<ProxyArgs> {
    let matches = build_cli().get_matches();

    let genkey = matches.get_flag("genkey");
    let username = matches.get_one::<String>("username").cloned();
    let stats_port = matches.get_one::<u16>("stats_port").copied().unwrap();

    let http_ports = matches
        .get_many::<u16>("http_ports")
        .map(|values| values.copied().collect::<Vec<_>>())
        .unwrap_or_default();

    let secrets: Vec<String> = matches
        .get_many::<String>("secret")
        .map(|values| values.cloned().collect())
        .unwrap_or_default();

    // Validate secrets
    for secret in &secrets {
        parse_hex_secret(secret).with_context(|| format!("Invalid secret: {}", secret))?;
    }

    // Support both proxy_tag and ad_tag (prefer proxy_tag if both are given)
    let proxy_tag = matches
        .get_one::<String>("proxy_tag")
        .cloned()
        .or_else(|| matches.get_one::<String>("ad_tag").cloned());

    if let Some(ref tag) = proxy_tag {
        parse_hex_secret(tag).with_context(|| format!("Invalid proxy tag: {}", tag))?;
    }

    let domains: Vec<String> = matches
        .get_many::<String>("domain")
        .map(|values| values.cloned().collect())
        .unwrap_or_default();

    let max_connections = matches
        .get_one::<String>("max_connections")
        .map(|v| v.parse::<u32>())
        .transpose()
        .context("Invalid max connections")?;

    let window_clamp = matches
        .get_one::<String>("window_clamp")
        .map(|v| v.parse::<u32>())
        .transpose()
        .context("Invalid window clamp")?;

    let workers = matches.get_one::<u32>("workers").copied().unwrap();

    let ping_interval = matches
        .get_one::<String>("ping_interval")
        .map(|v| v.parse::<f64>())
        .transpose()
        .context("Invalid ping interval")?
        .unwrap_or(DEFAULT_PING_INTERVAL);

    let aes_pwd_file = matches.get_one::<String>("aes_pwd_file").map(PathBuf::from);

    let config_file = matches.get_one::<String>("config").map(PathBuf::from);

    let http_stats = matches.get_flag("http_stats");

    // Basic validation (auto-download will be handled later if needed)
    if !genkey && !domains.is_empty() && secrets.is_empty() && aes_pwd_file.is_none() {
        anyhow::bail!(
            "Must specify at least one mtproto-secret or --aes-pwd when using TLS-transport"
        );
    }

    if workers > 1 && !domains.is_empty() {
        warn!("It is recommended to not use workers with TLS-transport");
    }

    Ok(ProxyArgs {
        username,
        stats_port,
        http_ports,
        secrets,
        proxy_tag,
        domains,
        max_connections,
        window_clamp,
        workers,
        ping_interval,
        aes_pwd_file,
        config_file,
        http_stats,
        genkey,
    })
}

fn generate_key() -> String {
    let mut key = [0u8; 16];
    getrandom::getrandom(&mut key).expect("Failed to generate random bytes");
    hex::encode(key)
}

async fn drop_privileges(username: &str) -> Result<()> {
    let user = nix::unistd::User::from_name(username)?
        .with_context(|| format!("User '{}' not found", username))?;

    info!(
        "Dropping privileges to user: {} (uid: {})",
        username, user.uid
    );

    setuid(user.uid).with_context(|| format!("Failed to setuid to {}", user.uid))?;

    Ok(())
}

async fn setup_signal_handlers() -> Result<()> {
    let mut sigterm = unix::signal(unix::SignalKind::terminate())?;
    let mut sigint = unix::signal(unix::SignalKind::interrupt())?;
    let mut sigusr1 = unix::signal(unix::SignalKind::user_defined1())?;

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = sigterm.recv() => {
                    info!("Received SIGTERM, shutting down gracefully");
                    std::process::exit(0);
                }
                _ = sigint.recv() => {
                    info!("Received SIGINT, shutting down gracefully");
                    std::process::exit(0);
                }
                _ = sigusr1.recv() => {
                    info!("Received SIGUSR1, reloading configuration");
                    // TODO: Implement config reload
                }
            }
        }
    });

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = parse_args().context("Failed to parse arguments")?;

    // Check if we should generate keys
    if args.genkey {
        let key = generate_key();
        println!("{}", key);
        return Ok(());
    }

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    info!("Starting mtproxy-rs v{}", VERSION);

    // Load or auto-download configuration
    let config = if let Some(ref config_file) = args.config_file {
        // Load from specified file
        Config::load(config_file)
            .await
            .context("Failed to load configuration")?
    } else {
        // Auto-download if no config file specified
        info!("No configuration file specified, auto-downloading from Telegram servers...");
        let config_content = Config::download_latest()
            .await
            .context("Failed to download configuration from Telegram servers")?;

        Config::parse_config(&config_content)?
    };

    // Load or auto-download AES secret if needed and add to secrets
    let mut args = args;

    if let Some(ref aes_pwd_file) = args.aes_pwd_file {
        // Load from specified file
        let aes_secret_raw = Config::load_aes_secret(aes_pwd_file)
            .await
            .context("Failed to load AES secret")?;

        // Take only the first 16 bytes (like the C version)
        let aes_secret = if aes_secret_raw.len() >= 16 {
            &aes_secret_raw[..16]
        } else {
            anyhow::bail!(
                "AES secret file must contain at least 16 bytes, got {}",
                aes_secret_raw.len()
            );
        };

        // Convert binary secret to hex string for compatibility with existing code
        let aes_secret_hex = hex::encode(aes_secret);
        info!(
            "Loaded AES secret from file: {} bytes -> hex: {}",
            aes_secret.len(),
            aes_secret_hex
        );
        args.secrets.push(aes_secret_hex);
        info!(
            "Loaded AES secret from file: {} ({} bytes, using first 16)",
            aes_pwd_file.display(),
            aes_secret_raw.len()
        );
    } else if args.secrets.is_empty() {
        // Try to auto-download proxy secret if no secrets specified and no AES file provided
        info!("No secrets specified, attempting to auto-download proxy secret from Telegram servers...");

        match Config::download_proxy_secret().await {
            Ok(aes_secret_raw) => {
                info!("Downloaded raw secret: {} bytes", aes_secret_raw.len());
                info!(
                    "Downloaded secret bytes: {:02x?}",
                    &aes_secret_raw[..std::cmp::min(32, aes_secret_raw.len())]
                );

                // Take only the first 16 bytes (like the C version)
                let aes_secret = if aes_secret_raw.len() >= 16 {
                    &aes_secret_raw[..16]
                } else {
                    anyhow::bail!(
                        "Downloaded secret must contain at least 16 bytes, got {}",
                        aes_secret_raw.len()
                    );
                };

                // Convert binary secret to hex string for compatibility with existing code
                let aes_secret_hex = hex::encode(aes_secret);
                info!("Converted secret to hex: {}", aes_secret_hex);
                args.secrets.push(aes_secret_hex);
                info!(
                    "Downloaded proxy secret ({} bytes, using first 16)",
                    aes_secret_raw.len()
                );
            }
            Err(e) => {
                warn!("Failed to auto-download proxy secret: {}", e);
                warn!("Auto-download endpoints may not be available. Generating a random secret for testing...");

                // Generate a random secret for testing/development
                let random_secret = generate_key();
                warn!("Generated random secret: {}", random_secret);
                warn!("⚠️  WARNING: This is a random secret for testing only!");
                warn!("⚠️  For production use, specify a secret with -S or --aes-pwd");

                args.secrets.push(random_secret);
            }
        }
    }

    // Debug log all configured secrets
    info!("Final configured secrets:");
    for (i, secret) in args.secrets.iter().enumerate() {
        info!("  Secret {}: {} (length: {})", i + 1, secret, secret.len());
        if let Ok(decoded) = hex::decode(secret) {
            info!("    Decoded: {:02x?}", decoded);
        } else {
            warn!("    Invalid hex format!");
        }
    }

    // Setup signal handlers
    setup_signal_handlers()
        .await
        .context("Failed to setup signal handlers")?;

    // Drop privileges if username specified
    if let Some(ref username) = args.username {
        drop_privileges(username)
            .await
            .context("Failed to drop privileges")?;
    }

    // Create and start the proxy engine
    let mut engine = Engine::new(args, config).await?;

    info!("MTProxy-RS started successfully");

    engine.run().await.context("Engine failed to run")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_secret() {
        // Valid secret
        let secret = "deadbeefcafebabe1234567890abcdef";
        let result = parse_hex_secret(secret).unwrap();
        let expected = [
            0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab,
            0xcd, 0xef,
        ];
        assert_eq!(result, expected);

        // Invalid length
        assert!(parse_hex_secret("deadbeef").is_err());
        assert!(parse_hex_secret("deadbeefcafebabe1234567890abcdef00").is_err());

        // Invalid hex characters
        assert!(parse_hex_secret("ggadbeefcafebabe1234567890abcdef").is_err());

        // Case sensitivity test
        let secret_upper = "DEADBEEFCAFEBABE1234567890ABCDEF";
        let result_upper = parse_hex_secret(secret_upper).unwrap();
        assert_eq!(result_upper, expected);

        // Mixed case
        let secret_mixed = "DeAdBeEfCaFeBaBe1234567890AbCdEf";
        let result_mixed = parse_hex_secret(secret_mixed).unwrap();
        assert_eq!(result_mixed, expected);
    }

    #[test]
    fn test_cli_parsing() {
        let app = build_cli();

        // Test basic valid command
        let matches = app
            .clone()
            .try_get_matches_from([
                "mtproxy-rs",
                "-u",
                "nobody",
                "-p",
                "8888",
                "-H",
                "443",
                "-S",
                "deadbeefcafebabe1234567890abcdef",
                "proxy-config.conf",
            ])
            .unwrap();

        assert_eq!(
            matches.get_one::<String>("username"),
            Some(&"nobody".to_string())
        );
        assert_eq!(matches.get_one::<u16>("stats_port"), Some(&8888));
    }

    #[test]
    fn test_cli_parsing_defaults() {
        let app = build_cli();

        // Test minimal command with defaults
        let matches = app
            .clone()
            .try_get_matches_from(["mtproxy-rs", "-S", "deadbeefcafebabe1234567890abcdef"])
            .unwrap();

        // Check default values
        assert_eq!(matches.get_one::<u16>("stats_port"), Some(&8888));
        assert_eq!(matches.get_one::<u32>("workers"), Some(&1));
        assert_eq!(matches.get_flag("http_stats"), false);
    }

    #[test]
    fn test_cli_parsing_multiple_ports() {
        let app = build_cli();

        // Test with multiple HTTP ports
        let matches = app
            .clone()
            .try_get_matches_from([
                "mtproxy-rs",
                "-H",
                "443",
                "-H",
                "8080",
                "-H",
                "8443",
                "-S",
                "deadbeefcafebabe1234567890abcdef",
                "proxy-config.conf",
            ])
            .unwrap();

        let ports: Vec<u16> = matches
            .get_many::<u16>("http_ports")
            .unwrap()
            .copied()
            .collect();
        assert_eq!(ports.len(), 3);
        assert!(ports.contains(&443));
        assert!(ports.contains(&8080));
        assert!(ports.contains(&8443));
    }

    #[test]
    fn test_cli_parsing_multiple_secrets() {
        let app = build_cli();

        // Test with multiple secrets
        let matches = app
            .clone()
            .try_get_matches_from([
                "mtproxy-rs",
                "-S",
                "deadbeefcafebabe1234567890abcdef",
                "-S",
                "1234567890abcdefdeadbeefcafebabe",
                "-H",
                "443",
            ])
            .unwrap();

        let secrets: Vec<&String> = matches.get_many::<String>("secret").unwrap().collect();
        assert_eq!(secrets.len(), 2);
        assert!(secrets.contains(&&"deadbeefcafebabe1234567890abcdef".to_string()));
        assert!(secrets.contains(&&"1234567890abcdefdeadbeefcafebabe".to_string()));
    }

    #[test]
    fn test_cli_parsing_domains() {
        let app = build_cli();

        // Test with domains instead of secrets
        let matches = app
            .clone()
            .try_get_matches_from([
                "mtproxy-rs",
                "-H",
                "443",
                "-D",
                "example.com",
                "-D",
                "telegram.org",
                "proxy-config.conf",
            ])
            .unwrap();

        let domains: Vec<&String> = matches.get_many::<String>("domain").unwrap().collect();
        assert_eq!(domains.len(), 2);
        assert!(domains.contains(&&"example.com".to_string()));
        assert!(domains.contains(&&"telegram.org".to_string()));
    }

    #[test]
    fn test_cli_parsing_all_options() {
        let app = build_cli();

        // Test with all available options
        let matches = app
            .clone()
            .try_get_matches_from([
                "mtproxy-rs",
                "-u",
                "nobody",
                "-p",
                "9999",
                "-H",
                "443",
                "-H",
                "8080",
                "-S",
                "deadbeefcafebabe1234567890abcdef",
                "-P",
                "1234567890abcdefdeadbeefcafebabe",
                "-D",
                "example.com",
                "-C",
                "1000",
                "-W",
                "4096",
                "-M",
                "4",
                "-T",
                "30.5",
                "--aes-pwd",
                "/tmp/secret.key",
                "--http-stats",
                "config.conf",
            ])
            .unwrap();

        assert_eq!(
            matches.get_one::<String>("username"),
            Some(&"nobody".to_string())
        );
        assert_eq!(matches.get_one::<u16>("stats_port"), Some(&9999));

        let ports: Vec<u16> = matches
            .get_many::<u16>("http_ports")
            .unwrap()
            .copied()
            .collect();
        assert_eq!(ports.len(), 2);

        let secrets: Vec<&String> = matches.get_many::<String>("secret").unwrap().collect();
        assert_eq!(secrets.len(), 1);

        assert_eq!(
            matches.get_one::<String>("proxy_tag"),
            Some(&"1234567890abcdefdeadbeefcafebabe".to_string())
        );

        let domains: Vec<&String> = matches.get_many::<String>("domain").unwrap().collect();
        assert_eq!(domains.len(), 1);

        assert_eq!(
            matches.get_one::<String>("max_connections"),
            Some(&"1000".to_string())
        );
        assert_eq!(
            matches.get_one::<String>("window_clamp"),
            Some(&"4096".to_string())
        );
        assert_eq!(matches.get_one::<u32>("workers"), Some(&4));
        assert_eq!(
            matches.get_one::<String>("ping_interval"),
            Some(&"30.5".to_string())
        );
        assert_eq!(
            matches.get_one::<String>("aes_pwd_file"),
            Some(&"/tmp/secret.key".to_string())
        );
        assert_eq!(matches.get_flag("http_stats"), true);
        assert_eq!(
            matches.get_one::<String>("config"),
            Some(&"config.conf".to_string())
        );
    }

    #[test]
    fn test_cli_parsing_edge_cases() {
        let app = build_cli();

        // Test invalid port range (0 is not allowed)
        let result = app.clone().try_get_matches_from([
            "mtproxy-rs",
            "-H",
            "0", // Invalid port
            "-S",
            "deadbeefcafebabe1234567890abcdef",
            "proxy-config.conf",
        ]);
        assert!(result.is_err());

        // Test invalid port range (too high)
        let result = app.clone().try_get_matches_from([
            "mtproxy-rs",
            "-H",
            "65536", // Invalid port
            "-S",
            "deadbeefcafebabe1234567890abcdef",
            "proxy-config.conf",
        ]);
        assert!(result.is_err());

        // Test invalid stats port
        let result = app.clone().try_get_matches_from([
            "mtproxy-rs",
            "-p",
            "0", // Invalid stats port
            "-H",
            "443",
            "-S",
            "deadbeefcafebabe1234567890abcdef",
            "proxy-config.conf",
        ]);
        assert!(result.is_err());

        // Test non-numeric port
        let result = app.clone().try_get_matches_from([
            "mtproxy-rs",
            "-H",
            "abc", // Non-numeric port
            "-S",
            "deadbeefcafebabe1234567890abcdef",
            "proxy-config.conf",
        ]);
        assert!(result.is_err());

        // Test invalid stats port (too high)
        let result = app.clone().try_get_matches_from([
            "mtproxy-rs",
            "-p",
            "70000", // Invalid stats port
            "-S",
            "deadbeefcafebabe1234567890abcdef",
        ]);
        assert!(result.is_err());

        // Test invalid workers (0 not allowed)
        let result = app.clone().try_get_matches_from([
            "mtproxy-rs",
            "-M",
            "0", // Invalid workers
            "-S",
            "deadbeefcafebabe1234567890abcdef",
        ]);
        assert!(result.is_err());

        // Test invalid workers (too high)
        let result = app.clone().try_get_matches_from([
            "mtproxy-rs",
            "-M",
            "100", // Too many workers
            "-S",
            "deadbeefcafebabe1234567890abcdef",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_args_validation() {
        // Test ProxyArgs creation and validation logic indirectly
        // by testing the parse_hex_secret function used in parse_args

        // Test multiple hex secrets validation
        let secrets = vec![
            "deadbeefcafebabe1234567890abcdef",
            "1234567890abcdefdeadbeefcafebabe",
            "abcdef1234567890cafebabe12345678",
        ];

        for secret in &secrets {
            let result = parse_hex_secret(secret);
            assert!(result.is_ok(), "Secret {} should be valid", secret);
        }

        // Test invalid secrets
        let invalid_secrets = vec![
            "short",                               // Too short
            "deadbeefcafebabe1234567890abcdef00",  // Too long
            "ggadbeefcafebabe1234567890abcdef",    // Invalid hex
            "",                                    // Empty
            "deadbeef cafe babe 1234567890abcdef", // Contains spaces
        ];

        for secret in &invalid_secrets {
            let result = parse_hex_secret(secret);
            assert!(result.is_err(), "Secret {} should be invalid", secret);
        }
    }

    #[test]
    fn test_cli_help_and_version() {
        let app = build_cli();

        // Test version output
        let result = app
            .clone()
            .try_get_matches_from(["mtproxy-rs", "--version"]);
        // This should fail because the app exits after showing version
        assert!(result.is_err());

        // Test help output
        let result = app.clone().try_get_matches_from(["mtproxy-rs", "--help"]);
        // This should fail because the app exits after showing help
        assert!(result.is_err());
    }

    #[test]
    fn test_cli_parsing_long_forms() {
        let app = build_cli();

        // Test using long form arguments
        let matches = app
            .clone()
            .try_get_matches_from([
                "mtproxy-rs",
                "--user",
                "nobody",
                "--stats-port",
                "8888",
                "--http-ports",
                "443",
                "--mtproto-secret",
                "deadbeefcafebabe1234567890abcdef",
                "--proxy-tag",
                "1234567890abcdefdeadbeefcafebabe",
                "--domain",
                "example.com",
                "--max-special-connections",
                "1000",
                "--window-clamp",
                "4096",
                "--slaves",
                "2",
                "--ping-interval",
                "45.0",
                "--aes-pwd",
                "/tmp/secret",
                "--http-stats",
                "config.conf",
            ])
            .unwrap();

        assert_eq!(
            matches.get_one::<String>("username"),
            Some(&"nobody".to_string())
        );
        assert_eq!(matches.get_one::<u16>("stats_port"), Some(&8888));
        assert_eq!(matches.get_one::<u32>("workers"), Some(&2));
        assert!(matches.get_flag("http_stats"));
    }
}
