use anyhow::{Context, Result};
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};

/// Network utilities
pub mod network {
    use super::*;
    use std::net::SocketAddr;

    /// Check if a port is available for binding
    pub fn is_port_available(port: u16) -> bool {
        std::net::TcpListener::bind(("0.0.0.0", port)).is_ok()
    }

    /// Get the local IP address
    pub fn get_local_ip() -> Result<IpAddr> {
        // Try to connect to a remote address to determine local IP
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
        socket.connect("8.8.8.8:80")?;
        let local_addr = socket.local_addr()?;
        Ok(local_addr.ip())
    }

    /// Get the public IP address by querying external services
    pub async fn get_public_ip() -> Result<IpAddr> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?;

        // Try multiple services in order of preference
        let services = [
            "https://ipv4.icanhazip.com",
            "https://api.ipify.org",
            "https://ifconfig.me/ip",
            "https://checkip.amazonaws.com",
        ];

        for service in &services {
            match client.get(*service).send().await {
                Ok(response) if response.status().is_success() => {
                    if let Ok(text) = response.text().await {
                        let ip_str = text.trim();
                        if let Ok(ip) = ip_str.parse::<IpAddr>() {
                            return Ok(ip);
                        }
                    }
                }
                _ => continue,
            }
        }

        // Fallback to local IP if all external services fail
        warn!("Failed to get public IP from external services, falling back to local IP");
        get_local_ip()
    }

    /// Parse IP address with fallback
    pub fn parse_ip_address(addr: &str) -> Result<IpAddr> {
        addr.parse::<IpAddr>()
            .with_context(|| format!("Invalid IP address: {}", addr))
    }

    /// Validate socket address
    pub fn validate_socket_address(addr: &str) -> Result<SocketAddr> {
        addr.parse::<SocketAddr>()
            .with_context(|| format!("Invalid socket address: {}", addr))
    }

    /// Check if IP address is private
    pub fn is_private_ip(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => ipv4.is_private() || ipv4.is_loopback() || ipv4.is_link_local(),
            IpAddr::V6(ipv6) => {
                ipv6.is_loopback()
                    || (ipv6.segments()[0] & 0xfe00) == 0xfc00
                    || (ipv6.segments()[0] & 0xffc0) == 0xfe80
            }
        }
    }
}

/// File system utilities
pub mod fs {
    use super::*;
    use std::fs;

    /// Ensure directory exists
    pub fn ensure_dir_exists(path: &Path) -> Result<()> {
        if !path.exists() {
            fs::create_dir_all(path)
                .with_context(|| format!("Failed to create directory: {}", path.display()))?;
        }
        Ok(())
    }

    /// Get file size
    pub fn get_file_size(path: &Path) -> Result<u64> {
        let metadata = fs::metadata(path)
            .with_context(|| format!("Failed to get file metadata: {}", path.display()))?;
        Ok(metadata.len())
    }

    /// Check if file is executable
    pub fn is_executable(path: &Path) -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = fs::metadata(path) {
                let permissions = metadata.permissions();
                return permissions.mode() & 0o111 != 0;
            }
        }
        false
    }

    /// Safe file copy with verification
    pub fn safe_copy(from: &Path, to: &Path) -> Result<()> {
        let source_size = get_file_size(from)?;
        fs::copy(from, to)
            .with_context(|| format!("Failed to copy {} to {}", from.display(), to.display()))?;

        let dest_size = get_file_size(to)?;
        if source_size != dest_size {
            anyhow::bail!("File copy verification failed: size mismatch");
        }

        Ok(())
    }

    /// Get disk space information
    pub fn get_disk_space(_path: &Path) -> Result<(u64, u64)> {
        // Returns (available, total) in bytes
        // Simplified implementation
        Ok((1_000_000_000, 10_000_000_000)) // 1GB available, 10GB total
    }
}

/// Time utilities
pub mod time {
    use super::*;

    /// Get current Unix timestamp
    pub fn now_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Get current Unix timestamp in milliseconds
    pub fn now_timestamp_millis() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    /// Format duration in human-readable format
    pub fn format_duration(duration: Duration) -> String {
        let total_seconds = duration.as_secs();
        let days = total_seconds / 86400;
        let hours = (total_seconds % 86400) / 3600;
        let minutes = (total_seconds % 3600) / 60;
        let seconds = total_seconds % 60;

        if days > 0 {
            format!("{}d {}h {}m {}s", days, hours, minutes, seconds)
        } else if hours > 0 {
            format!("{}h {}m {}s", hours, minutes, seconds)
        } else if minutes > 0 {
            format!("{}m {}s", minutes, seconds)
        } else {
            format!("{}s", seconds)
        }
    }

    /// Parse duration from string (e.g., "1h30m", "45s")
    pub fn parse_duration(s: &str) -> Result<Duration> {
        let s = s.trim().to_lowercase();
        let mut total_seconds = 0u64;
        let mut current_number = String::new();

        for c in s.chars() {
            if c.is_ascii_digit() {
                current_number.push(c);
            } else if !current_number.is_empty() {
                let number: u64 = current_number
                    .parse()
                    .with_context(|| format!("Invalid number in duration: {}", current_number))?;

                let multiplier = match c {
                    's' => 1,
                    'm' => 60,
                    'h' => 3600,
                    'd' => 86400,
                    _ => anyhow::bail!("Invalid duration unit: {}", c),
                };

                total_seconds += number * multiplier;
                current_number.clear();
            }
        }

        // Handle case where string ends with a number (assume seconds)
        if !current_number.is_empty() {
            let number: u64 = current_number.parse()?;
            total_seconds += number;
        }

        Ok(Duration::from_secs(total_seconds))
    }

    /// Sleep with jitter to avoid thundering herd
    pub async fn sleep_with_jitter(base_duration: Duration, jitter_percent: f64) {
        let jitter = (base_duration.as_millis() as f64 * jitter_percent / 100.0) as u64;
        let jitter_duration = Duration::from_millis(rand::random::<u64>() % jitter);
        let total_duration = base_duration + jitter_duration;
        tokio::time::sleep(total_duration).await;
    }
}

/// String utilities
pub mod string {

    /// Convert bytes to human-readable format
    pub fn format_bytes(bytes: u64) -> String {
        const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB", "PB"];
        let mut size = bytes as f64;
        let mut unit_index = 0;

        while size >= 1024.0 && unit_index < UNITS.len() - 1 {
            size /= 1024.0;
            unit_index += 1;
        }

        if unit_index == 0 {
            format!("{} {}", bytes, UNITS[unit_index])
        } else {
            format!("{:.2} {}", size, UNITS[unit_index])
        }
    }

    /// Truncate string to specified length with ellipsis
    pub fn truncate(s: &str, max_len: usize) -> String {
        if s.len() <= max_len {
            s.to_string()
        } else {
            format!("{}...", &s[..max_len.saturating_sub(3)])
        }
    }

    /// Generate random string
    pub fn random_string(length: usize) -> String {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                                 abcdefghijklmnopqrstuvwxyz\
                                 0123456789";

        (0..length)
            .map(|_| {
                let idx = rand::random::<u8>() as usize % CHARSET.len();
                CHARSET[idx] as char
            })
            .collect()
    }

    /// Generate random hex string
    pub fn random_hex(length: usize) -> String {
        (0..length)
            .map(|_| format!("{:x}", rand::random::<u8>() % 16))
            .collect()
    }

    /// Escape string for shell command
    pub fn shell_escape(s: &str) -> String {
        format!("'{}'", s.replace('\'', "'\"'\"'"))
    }
}

/// Validation utilities
pub mod validation {
    use super::*;

    /// Validate hex string
    pub fn is_valid_hex(s: &str) -> bool {
        !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit())
    }

    /// Validate domain name
    pub fn is_valid_domain(domain: &str) -> bool {
        if domain.is_empty() || domain.len() > 253 {
            return false;
        }

        domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
    }

    /// Validate port number
    pub fn is_valid_port(port: u16) -> bool {
        port > 0
    }

    /// Validate MTProxy secret
    pub fn is_valid_mtproxy_secret(secret: &str) -> bool {
        secret.len() == 32 && is_valid_hex(secret)
    }

    /// Validate configuration
    pub fn validate_proxy_config(secrets: &[String], domains: &[String]) -> Result<()> {
        if secrets.is_empty() && domains.is_empty() {
            anyhow::bail!("Must specify at least one secret or domain");
        }

        for secret in secrets {
            if !is_valid_mtproxy_secret(secret) {
                anyhow::bail!("Invalid secret format: {}", secret);
            }
        }

        for domain in domains {
            if !is_valid_domain(domain) {
                anyhow::bail!("Invalid domain: {}", domain);
            }
        }

        Ok(())
    }
}

/// System utilities
pub mod system {
    use super::*;

    /// Get current process ID
    pub fn get_pid() -> u32 {
        std::process::id()
    }

    /// Check if running as root
    pub fn is_root() -> bool {
        unsafe { libc::getuid() == 0 }
    }

    /// Get current user name
    pub fn get_username() -> Option<String> {
        std::env::var("USER")
            .ok()
            .or_else(|| std::env::var("USERNAME").ok())
    }

    /// Get system uptime
    pub fn get_uptime() -> Result<Duration> {
        // Simplified implementation
        // In a real implementation, you would read from /proc/uptime on Linux
        Ok(Duration::from_secs(0))
    }

    /// Get available memory
    pub fn get_available_memory() -> Result<u64> {
        // Simplified implementation
        // In a real implementation, you would read from /proc/meminfo on Linux
        Ok(1_000_000_000) // 1GB
    }

    /// Get CPU count
    pub fn get_cpu_count() -> usize {
        num_cpus::get()
    }

    /// Set process priority
    pub fn set_priority(priority: i32) -> Result<()> {
        // Simplified implementation
        // In a real implementation, you would use setpriority()
        debug!("Setting process priority to: {}", priority);
        Ok(())
    }
}

/// Retry utilities
pub mod retry {
    use super::*;
    use std::future::Future;

    /// Retry configuration
    #[derive(Debug, Clone)]
    pub struct RetryConfig {
        pub max_attempts: usize,
        pub base_delay: Duration,
        pub max_delay: Duration,
        pub backoff_multiplier: f64,
    }

    impl Default for RetryConfig {
        fn default() -> Self {
            Self {
                max_attempts: 3,
                base_delay: Duration::from_millis(100),
                max_delay: Duration::from_secs(30),
                backoff_multiplier: 2.0,
            }
        }
    }

    /// Retry a function with exponential backoff
    pub async fn retry_with_backoff<T, E, F, Fut>(
        config: RetryConfig,
        mut operation: F,
    ) -> Result<T, E>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, E>>,
        E: std::fmt::Debug,
    {
        let mut delay = config.base_delay;

        for attempt in 1..=config.max_attempts {
            match operation().await {
                Ok(result) => return Ok(result),
                Err(error) => {
                    if attempt == config.max_attempts {
                        return Err(error);
                    }

                    warn!(
                        "Attempt {} failed: {:?}, retrying in {:?}",
                        attempt, error, delay
                    );
                    tokio::time::sleep(delay).await;

                    delay = std::cmp::min(
                        Duration::from_millis(
                            (delay.as_millis() as f64 * config.backoff_multiplier) as u64,
                        ),
                        config.max_delay,
                    );
                }
            }
        }

        unreachable!()
    }
}

/// Rate limiting utilities
pub mod rate_limit {
    use super::*;
    use std::sync::Mutex;
    use std::time::Instant;

    /// Simple token bucket rate limiter
    pub struct TokenBucket {
        capacity: u32,
        tokens: Mutex<u32>,
        refill_rate: u32, // tokens per second
        last_refill: Mutex<Instant>,
    }

    impl TokenBucket {
        pub fn new(capacity: u32, refill_rate: u32) -> Self {
            Self {
                capacity,
                tokens: Mutex::new(capacity),
                refill_rate,
                last_refill: Mutex::new(Instant::now()),
            }
        }

        pub fn try_consume(&self, tokens: u32) -> bool {
            self.refill();

            let mut current_tokens = self.tokens.lock().unwrap();
            if *current_tokens >= tokens {
                *current_tokens -= tokens;
                true
            } else {
                false
            }
        }

        fn refill(&self) {
            let now = Instant::now();
            let mut last_refill = self.last_refill.lock().unwrap();
            let elapsed = now.duration_since(*last_refill);

            if elapsed >= Duration::from_secs(1) {
                let new_tokens = (elapsed.as_secs() as u32) * self.refill_rate;
                let mut tokens = self.tokens.lock().unwrap();
                *tokens = std::cmp::min(self.capacity, *tokens + new_tokens);
                *last_refill = now;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_utils() {
        assert!(network::is_port_available(0)); // Port 0 should always be available for binding

        let ip = network::parse_ip_address("127.0.0.1").unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

        assert!(network::is_private_ip(&IpAddr::V4(Ipv4Addr::new(
            192, 168, 1, 1
        ))));
        assert!(!network::is_private_ip(&IpAddr::V4(Ipv4Addr::new(
            8, 8, 8, 8
        ))));
    }

    #[test]
    fn test_network_address_parsing() {
        // Test IP address parsing
        let ipv4 = network::parse_ip_address("192.168.1.1").unwrap();
        assert!(matches!(ipv4, IpAddr::V4(_)));

        let ipv6 = network::parse_ip_address("::1").unwrap();
        assert!(matches!(ipv6, IpAddr::V6(_)));

        // Test invalid addresses
        assert!(network::parse_ip_address("invalid.ip").is_err());
        assert!(network::parse_ip_address("999.999.999.999").is_err());

        // Test private IP detection for various ranges
        assert!(network::is_private_ip(&IpAddr::V4(Ipv4Addr::new(
            10, 0, 0, 1
        )))); // 10.0.0.0/8
        assert!(network::is_private_ip(&IpAddr::V4(Ipv4Addr::new(
            172, 16, 0, 1
        )))); // 172.16.0.0/12
        assert!(network::is_private_ip(&IpAddr::V4(Ipv4Addr::new(
            192, 168, 1, 1
        )))); // 192.168.0.0/16
        assert!(network::is_private_ip(&IpAddr::V4(Ipv4Addr::new(
            127, 0, 0, 1
        )))); // 127.0.0.0/8 (loopback)

        // Test public IPs
        assert!(!network::is_private_ip(&IpAddr::V4(Ipv4Addr::new(
            8, 8, 8, 8
        )))); // Google DNS
        assert!(!network::is_private_ip(&IpAddr::V4(Ipv4Addr::new(
            1, 1, 1, 1
        )))); // Cloudflare DNS
        assert!(!network::is_private_ip(&IpAddr::V4(Ipv4Addr::new(
            208, 67, 222, 222
        )))); // OpenDNS
    }

    #[test]
    fn test_time_utils() {
        let timestamp = time::now_timestamp();
        assert!(timestamp > 0);

        let duration = Duration::from_secs(3661);
        let formatted = time::format_duration(duration);
        assert_eq!(formatted, "1h 1m 1s");

        let parsed = time::parse_duration("1h30m").unwrap();
        assert_eq!(parsed, Duration::from_secs(5400));
    }

    #[test]
    fn test_string_utils() {
        assert_eq!(string::format_bytes(1024), "1.00 KB");
        assert_eq!(string::format_bytes(1048576), "1.00 MB");

        assert_eq!(string::truncate("hello world", 5), "he...");
        assert_eq!(string::truncate("hi", 10), "hi");

        let random = string::random_string(10);
        assert_eq!(random.len(), 10);

        let hex = string::random_hex(8);
        assert_eq!(hex.len(), 8);
        assert!(validation::is_valid_hex(&hex));
    }

    #[test]
    fn test_validation() {
        assert!(validation::is_valid_hex("deadbeef"));
        assert!(!validation::is_valid_hex("xyz"));

        assert!(validation::is_valid_domain("example.com"));
        assert!(!validation::is_valid_domain(""));
        assert!(!validation::is_valid_domain("invalid..domain"));

        assert!(validation::is_valid_port(80));
        assert!(!validation::is_valid_port(0));

        assert!(validation::is_valid_mtproxy_secret(
            "deadbeefcafebabe1234567890abcdef"
        ));
        assert!(!validation::is_valid_mtproxy_secret("short"));
    }

    #[test]
    fn test_system_utils() {
        let pid = system::get_pid();
        assert!(pid > 0);

        let cpu_count = system::get_cpu_count();
        assert!(cpu_count > 0);
    }

    #[tokio::test]
    async fn test_retry() {
        let config = retry::RetryConfig::default();
        let mut attempts = 0;

        let result = retry::retry_with_backoff(config, || {
            attempts += 1;
            async move {
                if attempts < 3 {
                    Result::<(), &str>::Err("failed")
                } else {
                    Ok(())
                }
            }
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(attempts, 3);
    }

    #[test]
    fn test_rate_limit() {
        let bucket = rate_limit::TokenBucket::new(10, 5);

        // Should be able to consume initial tokens
        assert!(bucket.try_consume(5));
        assert!(bucket.try_consume(5));

        // Should fail to consume more tokens
        assert!(!bucket.try_consume(1));
    }

    #[tokio::test]
    async fn test_ip_detection() {
        println!("Testing IP detection functionality...");

        // Test local IP detection
        match network::get_local_ip() {
            Ok(local_ip) => {
                println!("Local IP: {}", local_ip);
                println!("Is private: {}", network::is_private_ip(&local_ip));
                assert!(local_ip.to_string().len() > 0);
            }
            Err(e) => {
                println!("Failed to get local IP: {}", e);
            }
        }

        // Test public IP detection
        println!("Attempting to detect public IP...");
        match network::get_public_ip().await {
            Ok(public_ip) => {
                println!("✅ Public IP detected: {}", public_ip);
                println!("   Is private: {}", network::is_private_ip(&public_ip));

                // Verify it's a valid IP address
                assert!(public_ip.to_string().len() > 0);

                // For most internet connections, the public IP should not be private
                // (though this might fail in some test environments)
                if !network::is_private_ip(&public_ip) {
                    println!("   ✅ Successfully detected a public (non-private) IP");
                } else {
                    println!("   ⚠️  Detected IP appears to be private (might be behind NAT)");
                }
            }
            Err(e) => {
                println!("❌ Failed to get public IP: {}", e);
                // Don't fail the test since network access might be limited
            }
        }

        // Test hostname detection
        if let Ok(hostname) = std::env::var("HOSTNAME") {
            if !hostname.is_empty() && hostname != "localhost" {
                println!("Environment hostname: {}", hostname);
            }
        }

        // Test system hostname
        if let Ok(output) = std::process::Command::new("hostname").output() {
            if let Ok(hostname) = String::from_utf8(output.stdout) {
                let hostname = hostname.trim();
                if !hostname.is_empty() && hostname != "localhost" {
                    println!("System hostname: {}", hostname);
                }
            }
        }

        println!("IP detection test completed.");
    }

    #[tokio::test]
    async fn test_server_address_selection() {
        println!("Testing server address selection logic...");

        // Simulate what the engine does to select server address
        let mut server_address = String::new();

        // 1. Try to get local IP as immediate fallback
        if let Ok(local_ip) = network::get_local_ip() {
            if !network::is_private_ip(&local_ip) {
                server_address = local_ip.to_string();
                println!("Using local non-private IP: {}", server_address);
            } else {
                println!(
                    "Local IP {} is private, trying public IP detection...",
                    local_ip
                );

                // 2. Try to get public IP
                if let Ok(public_ip) = network::get_public_ip().await {
                    server_address = public_ip.to_string();
                    println!("✅ Using detected public IP: {}", server_address);
                } else {
                    server_address = "YOUR_SERVER_IP".to_string();
                    println!("⚠️  Failed to detect public IP, using placeholder");
                }
            }
        }

        // 3. Try environment variable as fallback
        if server_address == "YOUR_SERVER_IP" {
            if let Ok(hostname) = std::env::var("HOSTNAME") {
                if !hostname.is_empty() && hostname != "localhost" {
                    server_address = hostname;
                    println!("Using environment hostname: {}", server_address);
                }
            }
        }

        // 4. Try system hostname as final fallback
        if server_address == "YOUR_SERVER_IP" {
            if let Ok(output) = std::process::Command::new("hostname").output() {
                if let Ok(hostname) = String::from_utf8(output.stdout) {
                    let hostname = hostname.trim();
                    if !hostname.is_empty() && hostname != "localhost" {
                        server_address = hostname.to_string();
                        println!("Using system hostname: {}", server_address);
                    }
                }
            }
        }

        // Generate example connection URL
        let secret = "deadbeefcafebabe1234567890abcdef";
        let port = 443;
        let url = format!(
            "tg://proxy?server={}&port={}&secret={}",
            server_address, port, secret
        );

        println!("Generated connection URL: {}", url);
        assert!(
            !url.contains("YOUR_SERVER_IP"),
            "Should not contain placeholder"
        );
        assert!(
            url.contains(&server_address),
            "Should contain the detected server address"
        );
    }
}
