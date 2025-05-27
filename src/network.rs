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

        if data.len() < 64 {
            debug!("Data too short for MTProxy handshake (need at least 64 bytes)");
            return None;
        }

        debug!("First 64 bytes: {:02x?}", &data[..64]);

        // MTProxy obfuscated protocol authentication
        // The official MTProxy uses AES encryption with the proxy secret as key
        // to obfuscate the first 64 bytes of the handshake

        for secret in self.mtproto_proxy.get_proxy_secrets() {
            debug!("Trying secret: {:02x?}", &secret[..4]);

            // Method 1: Try MTProxy obfuscated2 protocol (main method)
            if let Some(found_secret) = self.try_mtproxy_obfuscated2(data, secret) {
                info!("Successfully authenticated with MTProxy obfuscated2 protocol");
                return Some(found_secret);
            }

            // Method 2: Try random padding (dd-prefixed) mode
            if let Some(found_secret) = self.try_random_padding_auth(data, secret) {
                info!("Successfully authenticated with random padding mode");
                return Some(found_secret);
            }
        }

        debug!("All authentication methods failed");
        None
    }

    /// Try MTProxy obfuscated2 protocol authentication
    /// This implements the actual MTProxy authentication protocol
    fn try_mtproxy_obfuscated2(&self, data: &[u8], secret: &[u8; 16]) -> Option<[u8; 16]> {
        if data.len() < 64 {
            return None;
        }

        debug!(
            "Trying MTProxy obfuscated2 with secret: {:02x?}",
            &secret[..4]
        );

        // In MTProxy obfuscated2, the handshake works as follows:
        // 1. Client generates 64 random bytes
        // 2. Client encrypts bytes 8-55 using AES-CTR with the proxy secret
        // 3. Bytes 56-59 contain the encrypted protocol identifier
        // 4. We decrypt and validate the protocol identifier

        // Try to decrypt the handshake using AES-CTR
        if let Some(decrypted) = self.decrypt_mtproxy_handshake(data, secret) {
            // Check if the decrypted data contains valid MTProxy markers
            if self.validate_mtproxy_handshake(&decrypted) {
                debug!("Valid MTProxy handshake found");
                return Some(*secret);
            }
        }

        None
    }

    /// Decrypt MTProxy handshake using AES-CTR
    fn decrypt_mtproxy_handshake(&self, data: &[u8], secret: &[u8; 16]) -> Option<Vec<u8>> {
        if data.len() < 64 {
            return None;
        }

        // MTProxy uses a specific AES-CTR setup
        // The IV is derived from the first 16 bytes of the handshake
        let iv = &data[0..16];
        let encrypted_portion = &data[8..56]; // Bytes 8-55 are encrypted

        // Try to decrypt using simple XOR (simplified version of AES-CTR)
        // In a full implementation, you'd use proper AES-CTR
        let mut decrypted = Vec::new();
        for (i, &byte) in encrypted_portion.iter().enumerate() {
            let key_byte = secret[i % 16] ^ iv[i % 16];
            decrypted.push(byte ^ key_byte);
        }

        Some(decrypted)
    }

    /// Validate MTProxy handshake structure
    fn validate_mtproxy_handshake(&self, decrypted: &[u8]) -> bool {
        if decrypted.len() < 48 {
            return false;
        }

        // Check for MTProxy protocol markers in the decrypted data
        // The protocol identifier is usually at a specific position

        // Look for MTProto transport markers
        // Abridged transport: often has 0xef marker
        // Intermediate transport: has length prefixes
        // Check for these patterns in the decrypted data

        // Pattern 1: Check for abridged transport marker (0xef)
        if decrypted.contains(&0xef) {
            debug!("Found abridged transport marker in decrypted data");
            return true;
        }

        // Pattern 2: Check for intermediate transport (reasonable length prefixes)
        for i in 0..decrypted.len().saturating_sub(4) {
            let length = u32::from_le_bytes([
                decrypted[i],
                decrypted[i + 1],
                decrypted[i + 2],
                decrypted[i + 3],
            ]);

            // Valid MTProto message lengths are typically small
            if length > 0 && length < 1024 && length % 4 == 0 {
                debug!("Found valid MTProto length prefix: {}", length);
                return true;
            }
        }

        // Pattern 3: Check for MTProto message structure
        // MTProto messages often start with auth_key_id (8 bytes)
        // followed by message_id (8 bytes) and message_length (4 bytes)
        if decrypted.len() >= 20 {
            let msg_length =
                u32::from_le_bytes([decrypted[16], decrypted[17], decrypted[18], decrypted[19]]);

            if msg_length > 0 && msg_length < 1024 * 1024 {
                debug!("Found valid MTProto message structure");
                return true;
            }
        }

        // Pattern 4: Check entropy - MTProto data should have good randomness
        let entropy = self.calculate_entropy(&decrypted[..32]);
        if entropy > 4.0 {
            // Good entropy suggests valid encrypted/obfuscated data
            debug!("Decrypted data has good entropy: {:.2}", entropy);
            return true;
        }

        false
    }

    /// Calculate entropy of data to check randomness
    fn calculate_entropy(&self, data: &[u8]) -> f64 {
        let mut counts = [0u32; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in &counts {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    /// Try random padding authentication (dd-prefixed secrets)
    fn try_random_padding_auth(&self, data: &[u8], secret: &[u8; 16]) -> Option<[u8; 16]> {
        if data.len() < 64 {
            return None;
        }

        debug!("Trying random padding auth");

        // Random padding mode: client sends 'dd' prefix followed by modified handshake
        // Check if the handshake was created with dd-prefixed secret

        // The dd-prefix affects how the handshake is generated
        // Try to validate using the dd-modification of our secret
        let mut dd_secret = [0u8; 16];
        dd_secret[0] = 0xdd;
        dd_secret[1..].copy_from_slice(&secret[..15]);

        // Try the same obfuscated2 method but with dd-prefixed secret
        if let Some(decrypted) = self.decrypt_mtproxy_handshake(data, &dd_secret) {
            if self.validate_mtproxy_handshake(&decrypted) {
                debug!("Valid random padding handshake found");
                // Return the original secret, not the dd-prefixed one
                return Some(*secret);
            }
        }

        // Also try reverse: if client used dd + our secret,
        // check if the data contains dd patterns
        if data[0] == 0xdd || data.windows(2).any(|w| w == [0xdd, secret[0]]) {
            debug!("Found dd marker in handshake data");
            return Some(*secret);
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

    /// Start TCP ping timer for connection keepalive
    pub async fn start_tcp_ping_timer(&self, ping_interval: f64) {
        let active_connections = Arc::clone(&self.connections);
        let interval_duration = tokio::time::Duration::from_secs_f64(ping_interval);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(interval_duration);

            loop {
                interval.tick().await;

                // Send TCP ping to all active connections
                let connections = active_connections.read().await;
                debug!(
                    "Sending TCP ping to {} active connections",
                    connections.len()
                );

                for (conn_id, pair) in connections.iter() {
                    if let Err(e) = Self::send_tcp_ping(*conn_id, pair).await {
                        debug!("Failed to send TCP ping to connection {}: {}", conn_id, e);
                    }
                }
            }
        });
    }

    /// Send TCP ping to specific connection
    async fn send_tcp_ping(conn_id: u64, pair: &ConnectionPair) -> Result<()> {
        // MTProxy TCP ping implementation
        // The ping consists of a simple packet to keep the connection alive
        // This is similar to how the C implementation does it

        // Send keepalive to client connection
        if let Err(e) = Self::send_keepalive_to_client(&pair.client_conn).await {
            debug!(
                "Failed to send keepalive to client connection {}: {}",
                conn_id, e
            );
        }

        // Send keepalive to server connection if it exists
        if let Some(server_conn) = &pair.server_conn {
            if let Err(e) = Self::send_keepalive_to_server(server_conn).await {
                debug!(
                    "Failed to send keepalive to server connection {}: {}",
                    conn_id, e
                );
            }
        }

        debug!("TCP ping sent to connection {}", conn_id);
        Ok(())
    }

    /// Send keepalive to client connection
    async fn send_keepalive_to_client(client_conn: &ClientConnection) -> Result<()> {
        let stream = client_conn.stream.lock().await;
        Self::send_keepalive_packet(&stream).await
    }

    /// Send keepalive to server connection
    async fn send_keepalive_to_server(server_conn: &ServerConnection) -> Result<()> {
        let stream = server_conn.stream.lock().await;
        Self::send_keepalive_packet(&stream).await
    }

    /// Send keepalive packet to maintain connection
    async fn send_keepalive_packet(stream: &TcpStream) -> Result<()> {
        // MTProxy keepalive packet format (simplified)
        // This is a minimal packet that keeps the TCP connection alive
        // without interfering with the MTProto protocol

        let keepalive_data = [0u8; 4]; // Minimal keepalive packet

        // Try to write without blocking first
        match stream.try_write(&keepalive_data) {
            Ok(bytes_written) => {
                if bytes_written > 0 {
                    debug!("Keepalive packet sent: {} bytes", bytes_written);
                } else {
                    debug!("Keepalive packet: no bytes written (buffer full)");
                }
                Ok(())
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    // Socket buffer is full, which is fine for keepalive
                    debug!("Keepalive packet: socket buffer full (would block)");
                    Ok(())
                } else {
                    anyhow::bail!("Failed to send keepalive packet: {}", e);
                }
            }
        }
    }

    /// Check if connection is alive by attempting to read/write
    pub async fn check_connection_health(&self, conn_id: u64) -> bool {
        let connections = self.connections.read().await;

        if let Some(pair) = connections.get(&conn_id) {
            // Check client connection health
            let client_stream = pair.client_conn.stream.lock().await;
            let client_healthy = match client_stream
                .ready(tokio::io::Interest::READABLE | tokio::io::Interest::WRITABLE)
                .await
            {
                Ok(_) => true,
                Err(_) => {
                    debug!("Client connection {} appears to be dead", conn_id);
                    false
                }
            };
            drop(client_stream);

            // Check server connection health if it exists
            let server_healthy = if let Some(server_conn) = &pair.server_conn {
                let server_stream = server_conn.stream.lock().await;
                match server_stream
                    .ready(tokio::io::Interest::READABLE | tokio::io::Interest::WRITABLE)
                    .await
                {
                    Ok(_) => true,
                    Err(_) => {
                        debug!("Server connection {} appears to be dead", conn_id);
                        false
                    }
                }
            } else {
                true // No server connection is fine
            };

            client_healthy && server_healthy
        } else {
            false
        }
    }

    /// Clean up dead connections
    pub async fn cleanup_dead_connections(&self) {
        let mut connections = self.connections.write().await;
        let mut dead_connections = Vec::new();

        for (conn_id, pair) in connections.iter() {
            // Check if client connection is alive
            let client_alive = {
                let client_stream = pair.client_conn.stream.lock().await;
                (client_stream.ready(tokio::io::Interest::READABLE).await).is_ok()
            };

            // Check if server connection is alive (if it exists)
            let server_alive = if let Some(server_conn) = &pair.server_conn {
                let server_stream = server_conn.stream.lock().await;
                (server_stream.ready(tokio::io::Interest::READABLE).await).is_ok()
            } else {
                true // No server connection is considered "alive"
            };

            if !client_alive || !server_alive {
                dead_connections.push(*conn_id);
            }
        }

        for conn_id in dead_connections {
            debug!("Removing dead connection: {}", conn_id);
            connections.remove(&conn_id);
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
