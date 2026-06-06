use anyhow::Result;
use axum::{
    extract::Request,
    http::StatusCode,
    middleware::{self, Next},
    response::{Html, IntoResponse, Json, Response},
    routing::get,
    Router,
};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::network::NetworkManager;

/// Authentication state for stats endpoint
#[derive(Clone)]
struct AuthState {
    token: Option<String>,
}

impl AuthState {
    fn new(token: Option<String>) -> Self {
        Self { token }
    }

    fn is_enabled(&self) -> bool {
        self.token.is_some()
    }

    fn validate(&self, provided_token: &str) -> bool {
        match &self.token {
            Some(expected) => {
                // Constant-time comparison to prevent timing attacks
                if expected.len() != provided_token.len() {
                    return false;
                }
                expected
                    .as_bytes()
                    .iter()
                    .zip(provided_token.as_bytes())
                    .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                    == 0
            }
            None => true, // No auth required
        }
    }
}

/// Connection-level statistics
#[derive(Debug)]
pub struct ConnectionStats {
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub messages_sent: AtomicU64,
    pub messages_received: AtomicU64,
    pub connection_time: SystemTime,
    pub last_activity: AtomicU64,
}

impl Default for ConnectionStats {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionStats {
    pub fn new() -> Self {
        Self {
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            messages_sent: AtomicU64::new(0),
            messages_received: AtomicU64::new(0),
            connection_time: SystemTime::now(),
            last_activity: AtomicU64::new(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            ),
        }
    }

    pub fn update_activity(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_activity.store(now, Ordering::Relaxed);
    }

    pub fn get_bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    pub fn get_bytes_received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }

    pub fn get_total_bytes(&self) -> u64 {
        self.get_bytes_sent() + self.get_bytes_received()
    }

    pub fn get_connection_duration(&self) -> Duration {
        SystemTime::now()
            .duration_since(self.connection_time)
            .unwrap_or_default()
    }
}

/// Global proxy statistics
#[derive(Debug, Default, Serialize)]
pub struct ProxyStats {
    pub uptime_seconds: u64,
    pub total_connections: u64,
    pub active_connections: u64,
    pub bytes_forwarded: u64,
    pub messages_forwarded: u64,
    pub connection_errors: u64,
    pub authentication_failures: u64,
    pub memory_usage_bytes: u64,
    pub cpu_usage_percent: f64,
    pub network_rx_bytes: u64,
    pub network_tx_bytes: u64,
    pub telegram_servers: Vec<ServerStatus>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServerStatus {
    pub address: String,
    pub connected: bool,
    pub latency_ms: Option<u64>,
    pub last_error: Option<String>,
}

/// Statistics server for HTTP endpoint
#[derive(Clone)]
pub struct StatsServer {
    network_manager: Arc<NetworkManager>,
    start_time: SystemTime,
    server_stats: Arc<RwLock<HashMap<String, ServerStatus>>>,
    auth_state: Arc<AuthState>,
}

impl StatsServer {
    pub fn new(network_manager: Arc<NetworkManager>, auth_token: Option<String>) -> Self {
        if let Some(ref _token) = auth_token {
            info!("Stats endpoint authentication enabled");
        } else {
            warn!("Stats endpoint authentication disabled - consider enabling with --stats-token");
        }

        Self {
            network_manager,
            start_time: SystemTime::now(),
            server_stats: Arc::new(RwLock::new(HashMap::new())),
            auth_state: Arc::new(AuthState::new(auth_token)),
        }
    }

    /// Start the statistics HTTP server
    pub async fn start(&self, port: u16, http_stats_enabled: bool) -> Result<()> {
        if !http_stats_enabled {
            info!("HTTP stats disabled, starting simple stats server");
            return self.start_simple_server(port).await;
        }

        info!("Starting HTTP stats server on port {}", port);

        // Create protected routes with authentication
        let protected_routes = Router::new()
            .route("/stats", get(handle_stats))
            .route("/prometheus", get(handle_prometheus))
            .layer(middleware::from_fn(create_auth_middleware(
                self.auth_state.clone(),
            )));

        // Public routes (no auth required)
        let public_routes = Router::new()
            .route("/", get(handle_root))
            .route("/health", get(handle_health));

        let app = Router::new().merge(protected_routes).merge(public_routes);

        let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).await?;

        info!("Stats server listening on http://127.0.0.1:{}", port);

        axum::serve(listener, app).await?;

        Ok(())
    }

    /// Start simple stats server (non-HTTP)
    async fn start_simple_server(&self, port: u16) -> Result<()> {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port)).await?;
        info!("Simple stats server listening on port {}", port);

        loop {
            match listener.accept().await {
                Ok((mut stream, addr)) => {
                    info!("Stats request from {}", addr);
                    let stats = self.collect_stats().await;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}",
                        serde_json::to_string_pretty(&stats).unwrap_or_default()
                    );

                    if let Err(e) =
                        tokio::io::AsyncWriteExt::write_all(&mut stream, response.as_bytes()).await
                    {
                        error!("Failed to write stats response: {}", e);
                    }
                }
                Err(e) => {
                    error!("Failed to accept stats connection: {}", e);
                }
            }
        }
    }

    /// Collect current statistics
    async fn collect_stats(&self) -> ProxyStats {
        let uptime = SystemTime::now()
            .duration_since(self.start_time)
            .unwrap_or_default()
            .as_secs();

        let network_stats = self.network_manager.get_stats();
        let active_connections = self.network_manager.get_active_connections().await as u64;

        let server_stats = self.server_stats.read().await;
        let telegram_servers: Vec<ServerStatus> = server_stats.values().cloned().collect();

        let (network_rx_bytes, network_tx_bytes) = self.get_network_stats();

        ProxyStats {
            uptime_seconds: uptime,
            active_connections,
            total_connections: network_stats.total_connections.load(Ordering::Relaxed),
            bytes_forwarded: network_stats.bytes_forwarded.load(Ordering::Relaxed),
            messages_forwarded: network_stats.messages_forwarded.load(Ordering::Relaxed),
            connection_errors: network_stats.connection_errors.load(Ordering::Relaxed),
            authentication_failures: network_stats
                .authentication_failures
                .load(Ordering::Relaxed),
            memory_usage_bytes: self.get_memory_usage(),
            cpu_usage_percent: self.get_cpu_usage(),
            network_rx_bytes,
            network_tx_bytes,
            telegram_servers,
        }
    }

    /// Format statistics as Prometheus metrics
    fn format_prometheus_metrics(&self, stats: &ProxyStats) -> String {
        format!(
            r#"# HELP mtproxy_uptime_seconds Total uptime in seconds
# TYPE mtproxy_uptime_seconds counter
mtproxy_uptime_seconds {}

# HELP mtproxy_connections_total Total number of connections
# TYPE mtproxy_connections_total counter
mtproxy_connections_total {}

# HELP mtproxy_connections_active Number of active connections
# TYPE mtproxy_connections_active gauge
mtproxy_connections_active {}

# HELP mtproxy_bytes_forwarded_total Total bytes forwarded
# TYPE mtproxy_bytes_forwarded_total counter
mtproxy_bytes_forwarded_total {}

# HELP mtproxy_messages_forwarded_total Total messages forwarded
# TYPE mtproxy_messages_forwarded_total counter
mtproxy_messages_forwarded_total {}

# HELP mtproxy_connection_errors_total Total connection errors
# TYPE mtproxy_connection_errors_total counter
mtproxy_connection_errors_total {}

# HELP mtproxy_auth_failures_total Total authentication failures
# TYPE mtproxy_auth_failures_total counter
mtproxy_auth_failures_total {}

# HELP mtproxy_memory_usage_bytes Memory usage in bytes
# TYPE mtproxy_memory_usage_bytes gauge
mtproxy_memory_usage_bytes {}

# HELP mtproxy_cpu_usage_percent CPU usage percentage
# TYPE mtproxy_cpu_usage_percent gauge
mtproxy_cpu_usage_percent {}
"#,
            stats.uptime_seconds,
            stats.total_connections,
            stats.active_connections,
            stats.bytes_forwarded,
            stats.messages_forwarded,
            stats.connection_errors,
            stats.authentication_failures,
            stats.memory_usage_bytes,
            stats.cpu_usage_percent,
        )
    }

    /// Get memory usage (simplified implementation)
    fn get_memory_usage(&self) -> u64 {
        // Read from /proc/self/status on Linux
        #[cfg(target_os = "linux")]
        {
            if let Ok(content) = std::fs::read_to_string("/proc/self/status") {
                for line in content.lines() {
                    if line.starts_with("VmRSS:") {
                        if let Some(size_str) = line.split_whitespace().nth(1) {
                            if let Ok(size_kb) = size_str.parse::<u64>() {
                                return size_kb * 1024; // Convert KB to bytes
                            }
                        }
                    }
                }
            }
        }
        0
    }

    /// Get CPU usage (simplified implementation)
    fn get_cpu_usage(&self) -> f64 {
        // Simplified: would need to track process CPU time over intervals
        // for accurate measurement
        0.0
    }

    /// Get network interface statistics
    fn get_network_stats(&self) -> (u64, u64) {
        #[cfg(target_os = "linux")]
        {
            if let Ok(content) = std::fs::read_to_string("/proc/net/dev") {
                let mut total_rx = 0u64;
                let mut total_tx = 0u64;

                for line in content.lines().skip(2) {
                    // Skip headers
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 10 {
                        // Skip loopback interface
                        if parts[0].starts_with("lo:") {
                            continue;
                        }

                        // RX bytes is at index 1, TX bytes at index 9
                        if let Ok(rx) = parts[1].parse::<u64>() {
                            total_rx += rx;
                        }
                        if let Ok(tx) = parts[9].parse::<u64>() {
                            total_tx += tx;
                        }
                    }
                }

                return (total_rx, total_tx);
            }
        }
        (0, 0)
    }

    /// Update server status
    pub async fn update_server_status(&self, address: String, status: ServerStatus) {
        let mut server_stats = self.server_stats.write().await;
        server_stats.insert(address, status);
    }

    /// Clone for async handlers
    fn clone(&self) -> Self {
        Self {
            network_manager: self.network_manager.clone(),
            start_time: self.start_time,
            server_stats: self.server_stats.clone(),
            auth_state: self.auth_state.clone(),
        }
    }
}

/// Create authentication middleware for protected routes
fn create_auth_middleware(
    auth_state: Arc<AuthState>,
) -> impl Fn(Request, Next) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>>
       + Clone {
    move |req: Request, next: Next| {
        let auth_state = auth_state.clone();
        Box::pin(async move {
            // If auth is not enabled, allow all requests
            if !auth_state.is_enabled() {
                return next.run(req).await;
            }

            // Extract Authorization header
            let auth_header = req
                .headers()
                .get("Authorization")
                .and_then(|h| h.to_str().ok());

            match auth_header {
                Some(header) if header.starts_with("Bearer ") => {
                    let token = &header[7..]; // Skip "Bearer "
                    if auth_state.validate(token) {
                        debug!("Stats authentication successful");
                        next.run(req).await
                    } else {
                        warn!("Stats authentication failed: invalid token");
                        (
                            StatusCode::UNAUTHORIZED,
                            Json(serde_json::json!({
                                "error": "Invalid authentication token"
                            })),
                        )
                            .into_response()
                    }
                }
                _ => {
                    warn!("Stats authentication failed: missing or malformed Authorization header");
                    (
                        StatusCode::UNAUTHORIZED,
                        Json(serde_json::json!({
                            "error": "Authentication required. Provide Bearer token in Authorization header"
                        }))
                    ).into_response()
                }
            }
        })
    }
}

/// Utility functions for statistics
pub mod utils {
    use super::*;

    /// Format bytes in human-readable format
    pub fn format_bytes(bytes: u64) -> String {
        const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
        let mut size = bytes as f64;
        let mut unit_index = 0;

        while size >= 1024.0 && unit_index < UNITS.len() - 1 {
            size /= 1024.0;
            unit_index += 1;
        }

        format!("{:.2} {}", size, UNITS[unit_index])
    }

    /// Format duration in human-readable format
    pub fn format_duration(duration: Duration) -> String {
        let seconds = duration.as_secs();
        let days = seconds / 86400;
        let hours = (seconds % 86400) / 3600;
        let minutes = (seconds % 3600) / 60;
        let secs = seconds % 60;

        if days > 0 {
            format!("{}d {}h {}m {}s", days, hours, minutes, secs)
        } else if hours > 0 {
            format!("{}h {}m {}s", hours, minutes, secs)
        } else if minutes > 0 {
            format!("{}m {}s", minutes, secs)
        } else {
            format!("{}s", secs)
        }
    }

    /// Calculate rate per second
    pub fn calculate_rate(total: u64, duration: Duration) -> f64 {
        if duration.as_secs() == 0 {
            0.0
        } else {
            total as f64 / duration.as_secs() as f64
        }
    }
}

// Standalone handler functions for axum
async fn handle_root() -> Result<Html<String>, StatusCode> {
    let html = r#"
<!DOCTYPE html>
<html>
<head>
    <title>MTProxy-RS Statistics</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body>
    <h1>MTProxy-RS Statistics</h1>
    <div>
        <h2>API Endpoints</h2>
        <ul>
            <li><a href="/stats">/stats</a> - JSON statistics</li>
            <li><a href="/health">/health</a> - Health check</li>
            <li><a href="/prometheus">/prometheus</a> - Prometheus metrics</li>
        </ul>
    </div>
</body>
</html>
    "#;

    Ok(Html(html.to_string()))
}

async fn handle_stats() -> Result<Json<serde_json::Value>, StatusCode> {
    let stats = serde_json::json!({
        "status": "ok",
        "active_connections": 0,
        "total_connections": 0,
        "bytes_forwarded": 0,
        "messages_forwarded": 0
    });

    Ok(Json(stats))
}

async fn handle_health() -> Result<Json<serde_json::Value>, StatusCode> {
    let health = serde_json::json!({
        "status": "healthy",
        "timestamp": SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    });

    Ok(Json(health))
}

async fn handle_prometheus() -> Result<String, StatusCode> {
    let metrics = r#"# HELP mtproxy_connections_active Active connections
# TYPE mtproxy_connections_active gauge
mtproxy_connections_active 0

# HELP mtproxy_connections_total Total connections
# TYPE mtproxy_connections_total counter
mtproxy_connections_total 0
"#;

    Ok(metrics.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_stats() {
        let stats = ConnectionStats::new();

        stats.bytes_sent.store(1024, Ordering::Relaxed);
        stats.bytes_received.store(2048, Ordering::Relaxed);

        assert_eq!(stats.get_bytes_sent(), 1024);
        assert_eq!(stats.get_bytes_received(), 2048);
        assert_eq!(stats.get_total_bytes(), 3072);
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(utils::format_bytes(1024), "1.00 KB");
        assert_eq!(utils::format_bytes(1024 * 1024), "1.00 MB");
        assert_eq!(utils::format_bytes(1024 * 1024 * 1024), "1.00 GB");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(utils::format_duration(Duration::from_secs(30)), "30s");
        assert_eq!(utils::format_duration(Duration::from_secs(90)), "1m 30s");
        assert_eq!(
            utils::format_duration(Duration::from_secs(3661)),
            "1h 1m 1s"
        );
    }

    #[test]
    fn test_calculate_rate() {
        let rate = utils::calculate_rate(100, Duration::from_secs(10));
        assert_eq!(rate, 10.0);

        let rate = utils::calculate_rate(100, Duration::from_secs(0));
        assert_eq!(rate, 0.0);
    }
}
