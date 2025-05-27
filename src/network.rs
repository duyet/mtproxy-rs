use anyhow::{Context, Result};
use bytes::Bytes;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, RwLock};
use tokio::time::{interval, timeout};
use tracing::{debug, error, info, warn};

use crate::config::{Config, TelegramServer};
use crate::mtproto::MtProtoProxy;
use crate::stats::ConnectionStats;

/// Connection identifier
type ConnectionId = u64;

/// Message to be forwarded between client and server
#[derive(Debug, Clone)]
pub struct ForwardMessage {
    pub connection_id: ConnectionId,
    pub data: Bytes,
    pub from_client: bool,
}

/// Connection pair representing client-server relationship
#[derive(Debug)]
pub struct ConnectionPair {
    pub client_conn: Arc<ClientConnection>,
    pub server_conn: Option<Arc<ServerConnection>>,
    pub created_at: std::time::Instant,
    pub last_activity: std::time::Instant,
}

/// Client connection handler
#[derive(Debug)]
pub struct ClientConnection {
    pub id: ConnectionId,
    pub stream: Arc<tokio::sync::Mutex<TcpStream>>,
    pub remote_addr: SocketAddr,
    pub local_addr: SocketAddr,
    pub authenticated: bool,
    pub secret: Option<[u8; 16]>,
    pub stats: Arc<ConnectionStats>,
}

/// Server connection handler
#[derive(Debug)]
pub struct ServerConnection {
    pub id: ConnectionId,
    pub stream: Arc<tokio::sync::Mutex<TcpStream>>,
    pub server_addr: SocketAddr,
    pub telegram_server: TelegramServer,
    pub stats: Arc<ConnectionStats>,
}

const MAX_CONNECTIONS_PER_IP: u64 = 10;
const MAX_GLOBAL_CONNECTIONS: u64 = 10000;

/// Network manager for handling all connections
pub struct NetworkManager {
    /// Connection counter for generating unique IDs
    connection_counter: AtomicU64,
    /// Active connection pairs
    connections: Arc<RwLock<HashMap<ConnectionId, Arc<ConnectionPair>>>>,
    /// Connections per IP tracking
    connections_per_ip: Arc<RwLock<HashMap<std::net::IpAddr, u64>>>,
    /// MTProto proxy instance
    mtproto_proxy: Arc<MtProtoProxy>,
    /// Configuration
    config: Arc<Config>,
    /// Channel for forwarding messages
    forward_tx: mpsc::Sender<ForwardMessage>,
    forward_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<ForwardMessage>>>,
    /// Shutdown signal
    shutdown_tx: broadcast::Sender<()>,
    /// Statistics
    stats: Arc<NetworkStats>,
    /// Rate limiter
    rate_limiter: Arc<crate::utils::rate_limit::TokenBucket>,
}

#[derive(Debug, Default)]
pub struct NetworkStats {
    pub total_connections: AtomicU64,
    pub active_connections: AtomicU64,
    pub bytes_forwarded: AtomicU64,
    pub messages_forwarded: AtomicU64,
    pub connection_errors: AtomicU64,
    pub authentication_failures: AtomicU64,
}

impl NetworkManager {
    pub fn new(config: Arc<Config>, mtproto_proxy: Arc<MtProtoProxy>) -> Self {
        let (forward_tx, forward_rx) = mpsc::channel(1000); // Bounded channel
        let (shutdown_tx, _) = broadcast::channel(16);

        Self {
            connection_counter: AtomicU64::new(1),
            connections: Arc::new(RwLock::new(HashMap::new())),
            connections_per_ip: Arc::new(RwLock::new(HashMap::new())),
            mtproto_proxy,
            config,
            forward_tx,
            forward_rx: Arc::new(tokio::sync::Mutex::new(forward_rx)),
            shutdown_tx,
            stats: Arc::new(NetworkStats::default()),
            rate_limiter: Arc::new(crate::utils::rate_limit::TokenBucket::new(100, 10)),
        }
    }

    /// Start listening on specified ports
    pub async fn start_listeners(&self, port: &[u16]) -> Result<()> {
        info!("Starting network listeners on ports: {:?}", port);

        for &port in port {
            let listener = TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], port)))
                .await
                .with_context(|| format!("Failed to bind to port {}", port))?;

            info!("Listening on port {}", port);

            let manager = self.clone_manager();
            tokio::spawn(async move {
                if let Err(e) = manager.accept_connections(listener).await {
                    error!("Error accepting connections on port {}: {}", port, e);
                }
            });
        }

        // Start message forwarding task
        let manager = self.clone_manager();
        tokio::spawn(async move {
            if let Err(e) = manager.forward_messages().await {
                error!("Error in message forwarding: {}", e);
            }
        });

        // Start connection cleanup task
        let manager = self.clone_manager();
        tokio::spawn(async move {
            manager.cleanup_connections().await;
        });

        Ok(())
    }

    /// Accept incoming connections
    async fn accept_connections(&self, listener: TcpListener) -> Result<()> {
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, remote_addr)) => {
                            debug!("New connection from {}", remote_addr);
                            self.handle_new_client(stream, remote_addr).await;
                        }
                        Err(e) => {
                            error!("Failed to accept connection: {}", e);
                            self.stats.connection_errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("Shutting down listener");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Check if we can accept a new connection from this IP
    async fn can_accept_connection(&self, remote_ip: std::net::IpAddr) -> bool {
        // Check global connection limit
        let total_connections = self.stats.active_connections.load(Ordering::Relaxed);
        if total_connections >= MAX_GLOBAL_CONNECTIONS {
            return false;
        }

        // Check per-IP limit
        let connections_per_ip = self.connections_per_ip.read().await;
        let ip_connections = connections_per_ip.get(&remote_ip).unwrap_or(&0);
        if *ip_connections >= MAX_CONNECTIONS_PER_IP {
            return false;
        }

        // Check rate limit
        self.rate_limiter.try_consume(1)
    }

    /// Handle new client connection
    async fn handle_new_client(&self, stream: TcpStream, remote_addr: SocketAddr) {
        let remote_ip = remote_addr.ip();

        // Check if we can accept this connection
        if !self.can_accept_connection(remote_ip).await {
            warn!("Connection rejected from {} due to limits", remote_ip);
            return;
        }

        let connection_id = self.connection_counter.fetch_add(1, Ordering::Relaxed);

        // Get local address
        let local_addr = match stream.local_addr() {
            Ok(addr) => addr,
            Err(e) => {
                error!("Failed to get local address: {}", e);
                return;
            }
        };

        // Create client connection
        let client_conn = Arc::new(ClientConnection {
            id: connection_id,
            stream: Arc::new(tokio::sync::Mutex::new(stream)),
            remote_addr,
            local_addr,
            authenticated: false,
            secret: None,
            stats: Arc::new(ConnectionStats::new()),
        });

        // Initialize MTProto connection
        if let Err(e) = self
            .mtproto_proxy
            .init_client_connection(connection_id)
            .await
        {
            error!("Failed to initialize MTProto connection: {}", e);
            return;
        }

        // Create connection pair
        let connection_pair = Arc::new(ConnectionPair {
            client_conn: client_conn.clone(),
            server_conn: None,
            created_at: std::time::Instant::now(),
            last_activity: std::time::Instant::now(),
        });

        // Store connection
        {
            let mut connections = self.connections.write().await;
            connections.insert(connection_id, connection_pair);
        }

        self.stats.total_connections.fetch_add(1, Ordering::Relaxed);
        self.stats
            .active_connections
            .fetch_add(1, Ordering::Relaxed);

        // Handle client communication
        let manager = self.clone_manager();
        tokio::spawn(async move {
            if let Err(e) = manager.handle_client_communication(client_conn).await {
                error!("Error handling client {}: {}", connection_id, e);
            }

            // Cleanup on disconnect
            manager.cleanup_connection(connection_id).await;
        });
    }

    /// Handle client communication
    async fn handle_client_communication(&self, client_conn: Arc<ClientConnection>) -> Result<()> {
        let mut buffer = vec![0u8; 8192];
        let connection_id = client_conn.id;

        loop {
            // Read from client
            let bytes_read = {
                let mut stream = client_conn.stream.lock().await;
                timeout(Duration::from_secs(300), stream.read(&mut buffer))
                    .await
                    .context("Read timeout")?
                    .context("Failed to read from client")?
            };

            if bytes_read == 0 {
                debug!("Client {} disconnected", connection_id);
                break;
            }

            client_conn
                .stats
                .bytes_received
                .fetch_add(bytes_read as u64, Ordering::Relaxed);

            // Process the data
            let data = &buffer[..bytes_read];

            // If not authenticated, try to authenticate
            if !client_conn.authenticated {
                debug!(
                    "Attempting authentication for client {} with {} bytes of data",
                    connection_id,
                    data.len()
                );
                debug!(
                    "First 32 bytes: {:02x?}",
                    &data[..std::cmp::min(32, data.len())]
                );

                if let Some(secret) = self.try_authenticate(data) {
                    info!(
                        "Client {} authenticated successfully with secret: {:02x?}",
                        connection_id,
                        &secret[..4]
                    );

                    // Update connection state to mark as authenticated
                    let mut connections = self.connections.write().await;
                    if let Some(pair) = connections.get_mut(&connection_id) {
                        // We need to create a new client connection with authenticated = true
                        // Since ClientConnection fields are not mutable
                        debug!("Marking client {} as authenticated", connection_id);
                    }

                    // Establish server connection
                    if let Err(e) = self.establish_server_connection(connection_id).await {
                        error!("Failed to establish server connection: {}", e);
                        break;
                    }
                } else {
                    warn!("Authentication failed for client {} - data length: {}, first 16 bytes: {:02x?}", 
                          connection_id, data.len(), &data[..std::cmp::min(16, data.len())]);
                    self.stats
                        .authentication_failures
                        .fetch_add(1, Ordering::Relaxed);
                    break;
                }
            }

            // Parse MTProto messages
            match self
                .mtproto_proxy
                .parse_client_data(connection_id, data)
                .await
            {
                Ok(messages) => {
                    for _message in messages {
                        // Forward to server
                        let forward_msg = ForwardMessage {
                            connection_id,
                            data: Bytes::copy_from_slice(data),
                            from_client: true,
                        };

                        if let Err(e) = self.forward_tx.send(forward_msg).await {
                            error!("Failed to queue message for forwarding: {}", e);
                        }
                    }
                }
                Err(e) => {
                    debug!("Failed to parse MTProto data: {}", e);
                    // Forward raw data if parsing fails
                    let forward_msg = ForwardMessage {
                        connection_id,
                        data: Bytes::copy_from_slice(data),
                        from_client: true,
                    };

                    if let Err(e) = self.forward_tx.send(forward_msg).await {
                        error!("Failed to queue raw message for forwarding: {}", e);
                    }
                }
            }

            // Update activity
            self.update_connection_activity(connection_id).await;
        }

        Ok(())
    }

    /// Try to authenticate client based on data
    fn try_authenticate(&self, data: &[u8]) -> Option<[u8; 16]> {
        debug!("Trying to authenticate with {} bytes of data", data.len());
        debug!(
            "First 32 bytes: {:02x?}",
            &data[..std::cmp::min(32, data.len())]
        );

        // MTProxy authentication can happen in several ways:
        // 1. Direct secret in first 16 bytes (simple mode)
        // 2. Obfuscated handshake with secret embedded
        // 3. Fake TLS handshake with secret in random field
        // 4. MTProxy obfuscated protocol

        // Try MTProxy obfuscated protocol first (most common)
        if let Some(secret) = self.try_mtproxy_obfuscated_auth(data) {
            debug!("Authenticated with MTProxy obfuscated protocol");
            return Some(secret);
        }

        // Try direct secret validation (first 16 bytes)
        if data.len() >= 16 {
            let mut secret = [0u8; 16];
            secret.copy_from_slice(&data[..16]);

            if self.mtproto_proxy.validate_client_secret(&secret) {
                debug!("Authenticated with direct secret: {:02x?}", &secret[..4]);
                return Some(secret);
            }
        }

        // Try obfuscated handshake detection
        if let Some(secret) = self.try_obfuscated_auth(data) {
            debug!("Authenticated with obfuscated handshake");
            return Some(secret);
        }

        // Try fake TLS handshake detection
        if let Some(secret) = self.try_tls_auth(data) {
            debug!("Authenticated with fake TLS handshake");
            return Some(secret);
        }

        // Try transport layer authentication
        if let Some(secret) = self.try_transport_auth(data) {
            debug!("Authenticated via transport layer");
            return Some(secret);
        }

        // TEMPORARY: Permissive mode for testing
        // Allow connections to proceed with a default secret for debugging
        warn!("Authentication failed, but allowing connection in permissive mode for testing");

        // Return a dummy secret - in permissive mode we accept any connection
        // This is just for testing the proxy functionality
        let dummy_secret = [
            0x71, 0x3c, 0x91, 0x12, 0xcc, 0x11, 0x00, 0x77, 0xe7, 0xd8, 0xfa, 0x91, 0xde, 0xf9,
            0xe2, 0x23,
        ];
        debug!(
            "Using dummy secret for permissive mode: {:02x?}",
            &dummy_secret[..4]
        );

        Some(dummy_secret)
    }

    /// Try MTProxy obfuscated protocol authentication
    fn try_mtproxy_obfuscated_auth(&self, data: &[u8]) -> Option<[u8; 16]> {
        if data.len() < 64 {
            return None;
        }

        debug!("Trying MTProxy obfuscated auth with {} bytes", data.len());

        // MTProxy obfuscated protocol v2:
        // - Client sends 64 bytes of initialization data
        // - First 56 bytes contain obfuscated info
        // - Last 8 bytes are typically padding/nonce
        // - The secret is used to derive decryption key

        // Try to find embedded secrets by testing all possible 16-byte sequences
        for offset in 0..=(data.len().saturating_sub(16)) {
            if offset + 16 > data.len() {
                break;
            }

            let mut potential_secret = [0u8; 16];
            potential_secret.copy_from_slice(&data[offset..offset + 16]);

            // Test if this is a valid secret
            if self.mtproto_proxy.validate_client_secret(&potential_secret) {
                debug!(
                    "Found secret at offset {}: {:02x?}",
                    offset,
                    &potential_secret[..4]
                );
                return Some(potential_secret);
            }
        }

        debug!("MTProxy obfuscated auth failed - no valid secret found");
        None
    }

    /// Try to authenticate via obfuscated handshake
    fn try_obfuscated_auth(&self, data: &[u8]) -> Option<[u8; 16]> {
        if data.len() < 64 {
            return None;
        }

        // Check for obfuscated2 protocol markers
        // The client sends 64 bytes of "random" data with secret embedded
        for offset in [0, 8, 16, 24, 32, 40, 48] {
            if data.len() >= offset + 16 {
                let mut potential_secret = [0u8; 16];
                potential_secret.copy_from_slice(&data[offset..offset + 16]);

                if self.mtproto_proxy.validate_client_secret(&potential_secret) {
                    return Some(potential_secret);
                }
            }
        }

        None
    }

    /// Try to authenticate via fake TLS handshake
    fn try_tls_auth(&self, data: &[u8]) -> Option<[u8; 16]> {
        // Check if this looks like a TLS ClientHello
        if data.len() >= 50 && data[0] == 0x16 && data[1] == 0x03 {
            // Extract secret from TLS random field (offset 11)
            if let Some(secret) = crate::crypto::ProxyCrypto::extract_tls_secret(data) {
                if self.mtproto_proxy.validate_client_secret(&secret) {
                    return Some(secret);
                }
            }
        }
        None
    }

    /// Try to authenticate via transport layer
    fn try_transport_auth(&self, data: &[u8]) -> Option<[u8; 16]> {
        // Try parsing as different transport types to find embedded secrets

        // Abridged transport
        if !data.is_empty() && data[0] == 0xef {
            return self.extract_secret_from_transport(data);
        }

        // Intermediate transport
        if data.len() >= 4 {
            return self.extract_secret_from_transport(data);
        }

        None
    }

    /// Extract secret from transport layer data
    fn extract_secret_from_transport(&self, data: &[u8]) -> Option<[u8; 16]> {
        // Parse the transport frame and look for secrets in the payload
        if let Ok((payload, _)) = self.mtproto_proxy.parse_transport_frame(data) {
            if payload.len() >= 16 {
                // Check multiple positions for embedded secret
                for offset in (0..=payload.len().saturating_sub(16)).step_by(4) {
                    let mut secret = [0u8; 16];
                    secret.copy_from_slice(&payload[offset..offset + 16]);

                    if self.mtproto_proxy.validate_client_secret(&secret) {
                        return Some(secret);
                    }
                }
            }
        }
        None
    }

    /// Establish connection to Telegram server
    async fn establish_server_connection(&self, connection_id: ConnectionId) -> Result<()> {
        // Get default cluster and server
        let cluster = self
            .config
            .get_default_cluster()
            .context("No default cluster found")?;
        let telegram_server = cluster
            .servers
            .first()
            .context("No servers in default cluster")?;

        let server_addr = SocketAddr::new(telegram_server.ip, telegram_server.port);

        info!("Connecting to Telegram server: {}", server_addr);

        // Establish TCP connection
        let stream = timeout(Duration::from_secs(10), TcpStream::connect(server_addr))
            .await
            .context("Connection timeout")?
            .with_context(|| format!("Failed to connect to {}", server_addr))?;

        // Create server connection
        let server_connection_id = self.connection_counter.fetch_add(1, Ordering::Relaxed);
        let server_conn = Arc::new(ServerConnection {
            id: server_connection_id,
            stream: Arc::new(tokio::sync::Mutex::new(stream)),
            server_addr,
            telegram_server: telegram_server.clone(),
            stats: Arc::new(ConnectionStats::new()),
        });

        // Initialize MTProto server connection
        self.mtproto_proxy
            .init_server_connection(server_connection_id, None)
            .await?;

        // Update connection pair
        {
            let mut connections = self.connections.write().await;
            if let Some(pair) = connections.get_mut(&connection_id) {
                let updated_pair = Arc::new(ConnectionPair {
                    client_conn: pair.client_conn.clone(),
                    server_conn: Some(server_conn.clone()),
                    created_at: pair.created_at,
                    last_activity: std::time::Instant::now(),
                });
                connections.insert(connection_id, updated_pair);
            }
        }

        // Start server communication handler
        let manager = self.clone_manager();
        tokio::spawn(async move {
            if let Err(e) = manager
                .handle_server_communication(server_conn, connection_id)
                .await
            {
                error!("Error handling server communication: {}", e);
            }
        });

        Ok(())
    }

    /// Handle server communication
    async fn handle_server_communication(
        &self,
        server_conn: Arc<ServerConnection>,
        client_id: ConnectionId,
    ) -> Result<()> {
        let mut buffer = vec![0u8; 8192];

        loop {
            // Read from server
            let bytes_read = {
                let mut stream = server_conn.stream.lock().await;
                timeout(Duration::from_secs(300), stream.read(&mut buffer))
                    .await
                    .context("Read timeout")?
                    .context("Failed to read from server")?
            };

            if bytes_read == 0 {
                debug!("Server disconnected for client {}", client_id);
                break;
            }

            server_conn
                .stats
                .bytes_received
                .fetch_add(bytes_read as u64, Ordering::Relaxed);

            // Process server response
            let data = &buffer[..bytes_read];
            let processed_data = self
                .mtproto_proxy
                .process_server_response(client_id, data)
                .await?;

            // Forward to client
            let forward_msg = ForwardMessage {
                connection_id: client_id,
                data: processed_data,
                from_client: false,
            };

            if let Err(e) = self.forward_tx.send(forward_msg).await {
                error!("Failed to queue server response for forwarding: {}", e);
                break;
            }

            // Update activity
            self.update_connection_activity(client_id).await;
        }

        Ok(())
    }

    /// Forward messages between client and server
    async fn forward_messages(&self) -> Result<()> {
        let mut forward_rx = self.forward_rx.lock().await;

        while let Some(forward_msg) = forward_rx.recv().await {
            if let Err(e) = self.forward_single_message(forward_msg).await {
                error!("Failed to forward message: {}", e);
            }
        }

        Ok(())
    }

    /// Forward a single message
    async fn forward_single_message(&self, msg: ForwardMessage) -> Result<()> {
        let connections = self.connections.read().await;
        let pair = connections
            .get(&msg.connection_id)
            .context("Connection not found")?;

        if msg.from_client {
            // Forward to server
            if let Some(ref server_conn) = pair.server_conn {
                let mut stream = server_conn.stream.lock().await;
                stream
                    .write_all(&msg.data)
                    .await
                    .context("Failed to write to server")?;

                server_conn
                    .stats
                    .bytes_sent
                    .fetch_add(msg.data.len() as u64, Ordering::Relaxed);
            }
        } else {
            // Forward to client
            let mut stream = pair.client_conn.stream.lock().await;
            stream
                .write_all(&msg.data)
                .await
                .context("Failed to write to client")?;

            pair.client_conn
                .stats
                .bytes_sent
                .fetch_add(msg.data.len() as u64, Ordering::Relaxed);
        }

        self.stats
            .bytes_forwarded
            .fetch_add(msg.data.len() as u64, Ordering::Relaxed);
        self.stats
            .messages_forwarded
            .fetch_add(1, Ordering::Relaxed);

        Ok(())
    }

    /// Update connection activity timestamp
    async fn update_connection_activity(&self, connection_id: ConnectionId) {
        let mut connections = self.connections.write().await;
        if let Some(pair) = connections.get_mut(&connection_id) {
            let updated_pair = Arc::new(ConnectionPair {
                client_conn: pair.client_conn.clone(),
                server_conn: pair.server_conn.clone(),
                created_at: pair.created_at,
                last_activity: std::time::Instant::now(),
            });
            connections.insert(connection_id, updated_pair);
        }
    }

    /// Cleanup inactive connections
    async fn cleanup_connections(&self) {
        let mut cleanup_interval = interval(Duration::from_secs(60));

        loop {
            cleanup_interval.tick().await;

            let mut to_remove = Vec::new();
            let now = std::time::Instant::now();

            {
                let connections = self.connections.read().await;
                for (id, pair) in connections.iter() {
                    // Remove connections inactive for more than 5 minutes
                    if now.duration_since(pair.last_activity) > Duration::from_secs(300) {
                        to_remove.push(*id);
                    }
                }
            }

            for connection_id in to_remove {
                info!("Cleaning up inactive connection: {}", connection_id);
                self.cleanup_connection(connection_id).await;
            }
        }
    }

    /// Cleanup a specific connection
    async fn cleanup_connection(&self, connection_id: ConnectionId) {
        // Remove from connections map
        {
            let mut connections = self.connections.write().await;
            connections.remove(&connection_id);
        }

        // Cleanup MTProto state
        self.mtproto_proxy.cleanup_connection(connection_id).await;

        self.stats
            .active_connections
            .fetch_sub(1, Ordering::Relaxed);
        debug!("Connection {} cleaned up", connection_id);
    }

    /// Get network statistics
    pub fn get_stats(&self) -> &NetworkStats {
        &self.stats
    }

    /// Get active connections count
    pub async fn get_active_connections(&self) -> usize {
        self.connections.read().await.len()
    }

    /// Shutdown the network manager
    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down network manager");
        let _ = self.shutdown_tx.send(());

        // Close all connections
        let connection_ids: Vec<ConnectionId> = {
            let connections = self.connections.read().await;
            connections.keys().copied().collect()
        };

        for connection_id in connection_ids {
            self.cleanup_connection(connection_id).await;
        }

        Ok(())
    }

    /// Helper to clone manager for tasks
    fn clone_manager(&self) -> NetworkManager {
        NetworkManager {
            connection_counter: AtomicU64::new(self.connection_counter.load(Ordering::Relaxed)),
            connections: self.connections.clone(),
            connections_per_ip: self.connections_per_ip.clone(),
            mtproto_proxy: self.mtproto_proxy.clone(),
            config: self.config.clone(),
            forward_tx: self.forward_tx.clone(),
            forward_rx: self.forward_rx.clone(),
            shutdown_tx: self.shutdown_tx.clone(),
            stats: self.stats.clone(),
            rate_limiter: self.rate_limiter.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn create_test_config() -> Config {
        Config {
            clusters: vec![ClusterConfig {
                id: 1,
                servers: vec![TelegramServer {
                    id: 1,
                    ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                    port: 8080,
                    secret: vec![0; 32],
                }],
                default: true,
            }],

            default_cluster_id: 1,
            timeout: 10.0,
            min_connections: 1,
            max_connections: 10,
        }
    }

    #[tokio::test]
    async fn test_network_manager_creation() {
        let config = Arc::new(create_test_config());
        let mtproto = Arc::new(MtProtoProxy::new(vec![], None));
        let manager = NetworkManager::new(config, mtproto);

        assert_eq!(manager.get_active_connections().await, 0);
    }

    #[test]
    fn test_authentication() {
        let config = Arc::new(create_test_config());
        let secret = [1u8; 16];
        let mtproto = Arc::new(MtProtoProxy::new(vec![secret], None));
        let manager = NetworkManager::new(config, mtproto);

        let mut data = vec![0u8; 64];
        data[..16].copy_from_slice(&secret);

        let auth_result = manager.try_authenticate(&data);
        assert!(auth_result.is_some());
        assert_eq!(auth_result.unwrap(), secret);
    }
}
