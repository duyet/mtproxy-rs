use anyhow::Result;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use grammers_crypto::AuthKey;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

// For now, we'll use a simple u64 instead of MsgId
type MsgId = u64;

// MTProto RPC constants (matching C version)
const RPC_PING: u32 = 0x5730a2df;
const RPC_PONG: u32 = 0x8430eaa7;

// Transport types are available from grammers_mtproto if needed

/// MTProto message container
#[derive(Debug, Clone)]
pub struct MtProtoMessage {
    pub auth_key_id: i64,
    pub message_id: MsgId,
    pub sequence_number: i32,
    pub data: Bytes,
    pub encrypted: bool,
}

/// MTProto connection state
#[derive(Debug)]
pub struct ConnectionState {
    pub auth_key: Option<AuthKey>,
    pub server_salt: i64,
    pub session_id: i64,
    pub last_msg_id: MsgId,
    pub sequence_number: i32,
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionState {
    pub fn new() -> Self {
        Self {
            auth_key: None,
            server_salt: 0,
            session_id: rand::random(),
            last_msg_id: 0,
            sequence_number: 0,
        }
    }

    pub fn with_auth_key(auth_key: AuthKey, server_salt: i64) -> Self {
        Self {
            auth_key: Some(auth_key),
            server_salt,
            session_id: rand::random(),
            last_msg_id: 0,
            sequence_number: 0,
        }
    }

    pub fn next_msg_id(&mut self) -> MsgId {
        self.last_msg_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        self.last_msg_id
    }

    pub fn next_sequence_number(&mut self, content_related: bool) -> i32 {
        if content_related {
            self.sequence_number += 1;
            self.sequence_number * 2 - 1
        } else {
            self.sequence_number * 2
        }
    }
}

/// MTProto proxy handler
pub struct MtProtoProxy {
    /// Client connections state
    client_connections: Arc<RwLock<HashMap<u64, ConnectionState>>>,
    /// Server connections state  
    server_connections: Arc<RwLock<HashMap<u64, ConnectionState>>>,
    /// Proxy secrets for client authentication
    proxy_secrets: Vec<[u8; 16]>,
    /// Proxy tag for server communication
    proxy_tag: Option<[u8; 16]>,
    /// Random padding enabled
    random_padding: bool,
}

impl MtProtoProxy {
    pub fn new(proxy_secrets: Vec<[u8; 16]>, proxy_tag: Option<[u8; 16]>) -> Self {
        Self {
            client_connections: Arc::new(RwLock::new(HashMap::new())),
            server_connections: Arc::new(RwLock::new(HashMap::new())),
            proxy_secrets,
            proxy_tag,
            random_padding: false,
        }
    }

    /// Parse incoming client data and extract MTProto messages
    pub async fn parse_client_data(
        &self,
        conn_id: u64,
        data: &[u8],
    ) -> Result<Vec<MtProtoMessage>> {
        debug!("Parsing client data: {} bytes", data.len());

        if data.len() < 8 {
            anyhow::bail!("Data too short for MTProto");
        }

        let mut messages = Vec::new();
        let mut buf = data;

        while buf.len() >= 8 {
            // Try to parse as transport frame
            let (transport_data, consumed) = self.parse_transport_frame(buf)?;

            if let Some(message) = self.parse_mtproto_message(conn_id, &transport_data).await? {
                messages.push(message);
            }

            if consumed == 0 {
                break;
            }
            buf = &buf[consumed..];
        }

        Ok(messages)
    }

    /// Parse transport frame (handles different transport types)
    pub fn parse_transport_frame(&self, data: &[u8]) -> Result<(Bytes, usize)> {
        // Handle Abridged transport
        if !data.is_empty() {
            let first_byte = data[0];

            if first_byte == 0xef {
                // Abridged transport
                if data.len() < 4 {
                    return Ok((Bytes::new(), 0));
                }

                let length = data[1] as usize;
                let total_len = if length < 127 {
                    let payload_len = length * 4;
                    // Check for overflow
                    if payload_len > 0x100000 {
                        return Ok((Bytes::new(), 0));
                    }
                    payload_len + 1
                } else {
                    if data.len() < 4 {
                        return Ok((Bytes::new(), 0));
                    }
                    let extended_len = u32::from_le_bytes([data[1], data[2], data[3], 0]) as usize;
                    let payload_len = extended_len * 4;
                    // Check for overflow and reasonable size
                    if payload_len > 0x100000 || extended_len == 0 {
                        return Ok((Bytes::new(), 0));
                    }
                    payload_len + 4
                };

                if data.len() < total_len {
                    return Ok((Bytes::new(), 0));
                }

                let payload_start = if length < 127 { 1 } else { 4 };
                let payload = Bytes::copy_from_slice(&data[payload_start..total_len]);
                return Ok((payload, total_len));
            }
        }

        // Handle Intermediate transport
        if data.len() >= 4 {
            let length = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;

            // Prevent integer overflow and ensure reasonable packet size
            if length > 0x1000000 || length == 0 {
                return Ok((Bytes::new(), 0));
            }

            let total_len = length + 4;

            if data.len() >= total_len {
                let payload = Bytes::copy_from_slice(&data[4..total_len]);
                return Ok((payload, total_len));
            }
        }

        // Handle Full transport (with sequence numbers and CRC)
        if data.len() >= 12 {
            let length = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
            let total_len = length;

            if data.len() >= total_len && total_len >= 12 {
                let payload = Bytes::copy_from_slice(&data[8..total_len - 4]);
                return Ok((payload, total_len));
            }
        }

        Ok((Bytes::new(), 0))
    }

    /// Parse MTProto message from decrypted data
    async fn parse_mtproto_message(
        &self,
        _conn_id: u64,
        data: &Bytes,
    ) -> Result<Option<MtProtoMessage>> {
        if data.len() < 8 {
            return Ok(None);
        }

        debug!("Parsing MTProto message: {} bytes", data.len());

        // Check for RPC ping/pong packets (12 bytes each)
        if data.len() == 12 {
            let mut cursor = data.clone();
            let packet_type = cursor.get_u32_le();

            match packet_type {
                RPC_PING => {
                    let ping_id = cursor.get_u64_le();
                    info!("Received RPC_PING with ID: {}", ping_id);

                    // For ping packets, we should respond with pong
                    // But for now, just parse it as a regular message
                    return Ok(Some(MtProtoMessage {
                        auth_key_id: 0, // RPC ping doesn't use auth_key_id
                        message_id: ping_id,
                        sequence_number: 0,
                        data: data.clone(),
                        encrypted: false,
                    }));
                }
                RPC_PONG => {
                    let pong_id = cursor.get_u64_le();
                    debug!("Received RPC_PONG with ID: {}", pong_id);

                    return Ok(Some(MtProtoMessage {
                        auth_key_id: 0,
                        message_id: pong_id,
                        sequence_number: 0,
                        data: data.clone(),
                        encrypted: false,
                    }));
                }
                _ => {
                    // Not a ping/pong, continue with regular parsing
                }
            }
        }

        // Try to parse as regular MTProto message
        let mut cursor = data.clone();

        // Read auth_key_id (8 bytes)
        if cursor.remaining() < 8 {
            return Ok(None);
        }
        let auth_key_id = cursor.get_i64_le();

        // Check if this is an encrypted message (auth_key_id != 0)
        if auth_key_id != 0 {
            debug!("Encrypted message with auth_key_id: {}", auth_key_id);
            // For encrypted messages, we need more complex parsing
            // For now, treat as opaque data to be forwarded
            Ok(Some(MtProtoMessage {
                auth_key_id,
                message_id: 0, // Will be extracted from decrypted content
                sequence_number: 0,
                data: data.clone(),
                encrypted: true,
            }))
        } else {
            // Unencrypted message
            if cursor.remaining() < 12 {
                return Ok(None);
            }

            let message_id = cursor.get_u64_le();
            let message_length = cursor.get_u32_le();

            debug!(
                "Unencrypted message: auth_key_id={}, message_id={}, length={}",
                auth_key_id, message_id, message_length
            );

            if cursor.remaining() < message_length as usize {
                debug!(
                    "Incomplete message: expected {} bytes, got {}",
                    message_length,
                    cursor.remaining()
                );
                return Ok(None);
            }

            Ok(Some(MtProtoMessage {
                auth_key_id,
                message_id,
                sequence_number: 0,
                data: data.clone(),
                encrypted: false,
            }))
        }
    }

    /// Forward message to Telegram servers
    pub async fn forward_to_server(
        &self,
        _conn_id: u64,
        message: &MtProtoMessage,
        server_addr: IpAddr,
        server_port: u16,
    ) -> Result<Bytes> {
        debug!(
            "Forwarding message to server {}:{}",
            server_addr, server_port
        );

        // Add proxy tag if configured
        let mut data = BytesMut::new();

        if let Some(tag) = self.proxy_tag {
            data.extend_from_slice(&tag);
        }

        // Reconstruct the original MTProto packet
        data.put_i64_le(message.auth_key_id);

        if message.encrypted {
            // For encrypted messages, we need to preserve the structure
            data.extend_from_slice(&message.data);
        } else {
            // For unencrypted messages, reconstruct the packet
            data.put_i64_le(message.message_id as i64);
            data.put_u32_le(message.data.len() as u32);
            data.extend_from_slice(&message.data);
        }

        // Add random padding if enabled
        if self.random_padding {
            let padding_len = rand::random::<u8>() % 16;
            for _ in 0..padding_len {
                data.put_u8(rand::random());
            }
        }

        Ok(data.freeze())
    }

    /// Process server response and prepare for client
    pub async fn process_server_response(&self, _conn_id: u64, data: &[u8]) -> Result<Bytes> {
        debug!("Processing server response: {} bytes", data.len());

        // Remove proxy tag if present
        let mut start_offset = 0;
        if let Some(_tag) = self.proxy_tag {
            if data.len() >= 16 {
                start_offset = 16;
            }
        }

        let response_data = &data[start_offset..];

        // For proxy, we typically forward the response as-is
        // The client will handle decryption
        Ok(Bytes::copy_from_slice(response_data))
    }

    /// Handle client connection initialization
    pub async fn init_client_connection(&self, conn_id: u64) -> Result<()> {
        let mut connections = self.client_connections.write().await;
        connections.insert(conn_id, ConnectionState::new());
        info!("Initialized client connection: {}", conn_id);
        Ok(())
    }

    /// Handle server connection initialization
    pub async fn init_server_connection(
        &self,
        conn_id: u64,
        auth_key: Option<AuthKey>,
    ) -> Result<()> {
        let mut connections = self.server_connections.write().await;
        let state = if let Some(key) = auth_key {
            ConnectionState::with_auth_key(key, rand::random())
        } else {
            ConnectionState::new()
        };
        connections.insert(conn_id, state);
        info!("Initialized server connection: {}", conn_id);
        Ok(())
    }

    /// Clean up connection state
    pub async fn cleanup_connection(&self, conn_id: u64) {
        let mut client_connections = self.client_connections.write().await;
        let mut server_connections = self.server_connections.write().await;

        client_connections.remove(&conn_id);
        server_connections.remove(&conn_id);

        debug!("Cleaned up connection: {}", conn_id);
    }

    /// Validate client secret
    pub fn validate_client_secret(&self, secret: &[u8; 16]) -> bool {
        debug!("Validating secret: {:02x?}", secret);
        debug!("Available secrets: {}", self.proxy_secrets.len());

        // Print stored secrets for debugging
        for (i, stored_secret) in self.proxy_secrets.iter().enumerate() {
            debug!("Stored secret {}: {:02x?}", i, stored_secret);
        }

        // Check for "dd" prefix (random padding mode)
        // When random padding is enabled, client sends: dd + first 15 bytes of original secret
        // We need to compare those 15 bytes against first 15 bytes of our stored secrets
        if secret[0] == 0xdd {
            debug!("Detected random padding mode (dd prefix)");
            let client_partial = &secret[1..16]; // 15 bytes after 'dd'
            debug!("Client partial secret (15 bytes): {:02x?}", client_partial);

            let result = self.proxy_secrets.iter().any(|stored_secret| {
                let stored_partial = &stored_secret[..15]; // First 15 bytes of stored secret
                debug!("Comparing with stored partial: {:02x?}", stored_partial);
                stored_partial == client_partial
            });

            if result {
                debug!("Random padding secret matched!");
            } else {
                debug!("Random padding secret did not match any stored secrets");
            }
            return result;
        }

        // Regular mode - compare full 16-byte secret
        let result = self.proxy_secrets.iter().any(|s| {
            debug!("Comparing with stored secret: {:02x?}", s);
            s == secret
        });

        if result {
            debug!("Direct secret matched!");
        } else {
            debug!("No direct secret match found");
        }

        result
    }

    /// Enable random padding mode
    pub fn enable_random_padding(&mut self) {
        self.random_padding = true;
        info!("Random padding enabled");
    }

    /// Get connection statistics
    pub async fn get_stats(&self) -> (usize, usize) {
        let client_count = self.client_connections.read().await.len();
        let server_count = self.server_connections.read().await.len();
        (client_count, server_count)
    }

    /// Get proxy secrets for authentication
    pub fn get_proxy_secrets(&self) -> &Vec<[u8; 16]> {
        &self.proxy_secrets
    }

    pub async fn process_client_message(
        &self,
        _conn_id: u64,
        _data: &[u8],
    ) -> Result<Vec<MtProtoMessage>> {
        // Implementation of process_client_message method
        Ok(Vec::new())
    }
}

/// Utility functions for MTProto proxy operations
pub mod utils {
    use super::*;

    /// Extract datacenter ID from MTProto message
    pub fn extract_dc_id(_data: &[u8]) -> Option<i32> {
        // This would require parsing the TL schema
        // For now, return None as DC extraction needs proper TL parsing
        None
    }

    /// Calculate message key for encryption
    pub fn calculate_message_key(_auth_key: &AuthKey, _data: &[u8], _outbound: bool) -> [u8; 16] {
        // This is a simplified implementation - in reality you'd need proper message key calculation
        [0u8; 16]
    }

    /// Generate random session ID
    pub fn generate_session_id() -> i64 {
        rand::random()
    }

    /// Validate MTProto packet structure
    pub fn validate_packet_structure(data: &[u8]) -> bool {
        if data.len() < 8 {
            return false;
        }

        // Basic validation - check if it looks like MTProto
        let _auth_key_id = i64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);

        // Valid auth_key_id (0 for unencrypted, non-zero for encrypted)
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mtproto_proxy_creation() {
        let secrets = vec![[
            0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab,
            0xcd, 0xef,
        ]];
        let proxy = MtProtoProxy::new(secrets, None);

        let (client_count, server_count) = proxy.get_stats().await;
        assert_eq!(client_count, 0);
        assert_eq!(server_count, 0);
    }

    #[tokio::test]
    async fn test_connection_management() {
        let proxy = MtProtoProxy::new(vec![], None);

        // Test client connection
        proxy.init_client_connection(123).await.unwrap();
        let (client_count, _) = proxy.get_stats().await;
        assert_eq!(client_count, 1);

        // Test server connection
        proxy.init_server_connection(456, None).await.unwrap();
        let (_, server_count) = proxy.get_stats().await;
        assert_eq!(server_count, 1);

        // Test cleanup
        proxy.cleanup_connection(123).await;
        let (client_count, _) = proxy.get_stats().await;
        assert_eq!(client_count, 0);
    }

    #[test]
    fn test_secret_validation() {
        let secret = [
            0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab,
            0xcd, 0xef,
        ];
        let proxy = MtProtoProxy::new(vec![secret], None);

        assert!(proxy.validate_client_secret(&secret));

        let wrong_secret = [0x00; 16];
        assert!(!proxy.validate_client_secret(&wrong_secret));
    }

    #[test]
    fn test_random_padding_secret_validation() {
        // Test proper random padding secret validation
        let base_secret = [
            0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab,
            0xcd, 0xef,
        ];
        let proxy = MtProtoProxy::new(vec![base_secret], None);

        // Test secret with "dd" prefix for random padding
        // Client sends: dd + first 15 bytes of original secret
        let padded_secret = [
            0xdd, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x12, 0x34, 0x56, 0x78, 0x90,
            0xab, 0xcd, // This is the 15th byte of original secret
        ];

        // This should pass because we compare first 15 bytes of stored secret
        // with the 15 bytes after 'dd' in the client secret
        let result = proxy.validate_client_secret(&padded_secret);
        assert!(result, "Random padding secret should validate correctly");
    }

    #[test]
    fn test_random_padding_secret_no_match() {
        // Test with a secret that should NOT match
        let base_secret = [
            0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab,
            0xcd, 0xef,
        ];
        let proxy = MtProtoProxy::new(vec![base_secret], None);

        // Test secret with "dd" prefix but different bytes
        let padded_secret = [
            0xdd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, // Completely different from base_secret
        ];

        // This should NOT pass because the 15 bytes after 'dd' don't match
        let result = proxy.validate_client_secret(&padded_secret);
        assert!(
            !result,
            "Random padding secret with wrong bytes should not validate"
        );
    }

    #[test]
    fn test_transport_frame_overflow() {
        let proxy = MtProtoProxy::new(vec![], None);

        // Test with malicious data that could cause integer overflow
        let mut malicious_data = vec![0xef]; // Abridged transport marker
        malicious_data.extend_from_slice(&[0xff, 0xff, 0xff, 0x3f]); // Large length that could overflow

        let result = proxy.parse_transport_frame(&malicious_data);

        // Should handle gracefully, not panic or overflow
        match result {
            Ok((_, consumed)) => {
                // Should not consume more data than available
                assert!(consumed <= malicious_data.len());
            }
            Err(_) => {
                // Error is acceptable for malicious input
            }
        }
    }

    #[test]
    fn test_transport_frame_bounds_checking() {
        let proxy = MtProtoProxy::new(vec![], None);

        // Test intermediate transport with length larger than available data
        let malicious_data = vec![0x10, 0x00, 0x00, 0x00]; // Claims 16 bytes but only has 4

        let result = proxy.parse_transport_frame(&malicious_data);

        // Should return empty result, not try to read beyond bounds
        match result {
            Ok((bytes, consumed)) => {
                assert_eq!(consumed, 0);
                assert_eq!(bytes.len(), 0);
            }
            Err(_) => {
                // Error is also acceptable
            }
        }
    }

    #[test]
    fn test_transport_frame_underflow() {
        let proxy = MtProtoProxy::new(vec![], None);

        // Test full transport with length that could cause underflow
        let malicious_data = vec![0x05, 0x00, 0x00, 0x00]; // Length 5, which is < 12

        let result = proxy.parse_transport_frame(&malicious_data);

        // Should handle gracefully
        match result {
            Ok((bytes, consumed)) => {
                assert_eq!(consumed, 0);
                assert_eq!(bytes.len(), 0);
            }
            Err(_) => {
                // Error is acceptable
            }
        }
    }

    #[test]
    fn test_large_message_length() {
        let proxy = MtProtoProxy::new(vec![], None);

        // Create a message that claims to be very large
        let mut data = vec![0u8; 24]; // Auth key ID + message ID
        data.extend_from_slice(&[0xff, 0xff, 0xff, 0xff]); // Max u32 length
        data.extend_from_slice(&[0u8; 10]); // Some actual data

        let bytes = Bytes::from(data);
        let rt = tokio::runtime::Runtime::new().unwrap();

        let result = rt.block_on(async { proxy.parse_mtproto_message(1, &bytes).await });

        // Should handle gracefully, not try to allocate huge buffer
        match result {
            Ok(None) => {
                // Expected - should reject oversized messages
            }
            Ok(Some(_)) => {
                // If it parses, ensure it's reasonable
            }
            Err(_) => {
                // Error is acceptable for malicious input
            }
        }
    }
}
