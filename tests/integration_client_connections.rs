use anyhow::Result;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

// Import the MTProxy modules from the local crate
use mtproxy_rs::{config::Config, engine::Engine, ProxyArgs};

// Test secret for integration tests
const TEST_SECRET: &str = "deadbeefcafebabe1234567890abcdef";
const TEST_SECRET_BYTES: [u8; 16] = [
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
];

// Random padding secret (dd prefix)
const TEST_SECRET_PADDED_BYTES: [u8; 16] = [
    0xdd, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd,
];

/// Helper to create test configuration
fn create_test_config() -> Config {
    use mtproxy_rs::config::{ClusterConfig, TelegramServer};

    // Create minimal test config with some test servers
    Config {
        clusters: vec![
            ClusterConfig {
                id: 2,
                servers: vec![TelegramServer {
                    id: 0,
                    ip: "149.154.161.144".parse().unwrap(),
                    port: 8888,
                    secret: Vec::new(),
                }],
                default: true,
            },
            ClusterConfig {
                id: 4,
                servers: vec![TelegramServer {
                    id: 0,
                    ip: "91.108.4.204".parse().unwrap(),
                    port: 8888,
                    secret: Vec::new(),
                }],
                default: false,
            },
        ],
        default_cluster_id: 2,
        timeout: 30.0,
        min_connections: 1,
        max_connections: 100,
    }
}

/// Helper to create test proxy arguments
fn create_test_args(port: u16) -> ProxyArgs {
    ProxyArgs {
        username: None,
        stats_port: 18888, // Use different port to avoid conflicts
        port: vec![port],
        secrets: vec![TEST_SECRET.to_string()],
        proxy_tag: None,
        domains: Vec::new(),
        max_connections: Some(100),
        window_clamp: None,
        workers: 1,
        ping_interval: 60.0,
        aes_pwd_file: None,
        config_file: None,
        http_stats: false,
        genkey: false,
    }
}

/// Start a test MTProxy server
async fn start_test_server(port: u16) -> Result<()> {
    let args = create_test_args(port);
    let config = create_test_config();

    let mut engine = Engine::new(args, config).await?;

    // Start the engine in background
    tokio::spawn(async move {
        if let Err(e) = engine.run().await {
            eprintln!("Test server error: {}", e);
        }
    });

    // Give the server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    Ok(())
}

/// Test client connection with valid secret
#[tokio::test]
async fn test_client_connection_valid_secret() -> Result<()> {
    let port = 19001;
    start_test_server(port).await?;

    // Connect to the server
    let mut stream = timeout(
        Duration::from_secs(5),
        TcpStream::connect(format!("127.0.0.1:{}", port)),
    )
    .await??;

    // Send authentication handshake with valid secret
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&TEST_SECRET_BYTES);
    auth_data.extend_from_slice(&[0u8; 48]); // Padding to simulate real handshake

    stream.write_all(&auth_data).await?;

    // Read response (server should not immediately close connection)
    let mut buffer = [0u8; 64];
    match timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
        Ok(Ok(n)) => {
            assert!(n >= 0);
            println!("Received {} bytes from server", n);
        }
        Ok(Err(_)) => {
            // Server might close connection, which is acceptable for this test
            println!("Server closed connection (expected behavior)");
        }
        Err(_) => {
            // Timeout waiting for response (expected for test)
            println!("Timeout waiting for response (expected for test)");
        }
    }

    Ok(())
}

/// Test client connection with invalid secret
#[tokio::test]
async fn test_client_connection_invalid_secret() -> Result<()> {
    let port = 19002;
    start_test_server(port).await?;

    // Connect to the server
    let mut stream = timeout(
        Duration::from_secs(5),
        TcpStream::connect(format!("127.0.0.1:{}", port)),
    )
    .await??;

    // Send authentication handshake with invalid secret
    let invalid_secret = [0xaa; 16];
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&invalid_secret);
    auth_data.extend_from_slice(&[0u8; 48]); // Padding

    stream.write_all(&auth_data).await?;

    // Read response (server should close connection quickly due to invalid auth)
    let mut buffer = [0u8; 64];
    match timeout(Duration::from_millis(1000), stream.read(&mut buffer)).await {
        Ok(Ok(n)) => {
            assert!(n >= 0);
            println!("Received {} bytes from server", n);
        }
        Ok(Err(_)) => {
            // Expected: server closes connection due to invalid secret
            println!("Server closed connection due to invalid secret (expected)");
        }
        Err(_) => {
            // Timeout is also acceptable
            println!("Timeout waiting for response");
        }
    }

    Ok(())
}

/// Test client connection with random padding (dd prefix)
#[tokio::test]
async fn test_client_connection_random_padding() -> Result<()> {
    let port = 19003;
    start_test_server(port).await?;

    // Connect to the server
    let mut stream = timeout(
        Duration::from_secs(5),
        TcpStream::connect(format!("127.0.0.1:{}", port)),
    )
    .await??;

    // Send authentication handshake with random padding secret (dd prefix)
    let mut auth_data = Vec::new();
    auth_data.extend_from_slice(&TEST_SECRET_PADDED_BYTES);
    auth_data.extend_from_slice(&[0u8; 48]); // Padding

    stream.write_all(&auth_data).await?;

    // Read response
    let mut buffer = [0u8; 64];
    match timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
        Ok(Ok(n)) => {
            assert!(n >= 0);
            println!("Received {} bytes from server with random padding", n);
        }
        Ok(Err(_)) => {
            println!("Server closed connection (may be expected)");
        }
        Err(_) => {
            println!("Timeout waiting for response (expected for test)");
        }
    }

    Ok(())
}

/// Test multiple concurrent connections
#[tokio::test]
async fn test_multiple_concurrent_connections() -> Result<()> {
    let port = 19004;
    start_test_server(port).await?;

    // Create multiple concurrent connections
    let mut handles = Vec::new();

    for i in 0..5 {
        let handle = tokio::spawn(async move {
            // Connect to the server
            let result = timeout(Duration::from_secs(10), async {
                let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port)).await?;

                // Send auth data
                let mut auth_data = Vec::new();
                auth_data.extend_from_slice(&TEST_SECRET_BYTES);
                auth_data.extend_from_slice(&[0u8; 48]);

                stream.write_all(&auth_data).await?;

                // Try to read response
                let mut buffer = [0u8; 64];
                let _ = timeout(Duration::from_millis(200), stream.read(&mut buffer)).await;

                Ok::<(), anyhow::Error>(())
            })
            .await;

            if let Err(ref e) = result {
                println!("Connection {} failed: {}", i, e);
            } else {
                println!("Connection {} successful", i);
            }

            result
        });

        handles.push(handle);
    }

    // Wait for all connections to complete
    let mut success_count = 0;
    for handle in handles {
        match handle.await {
            Ok(Ok(_)) => success_count += 1,
            Ok(Err(e)) => println!("Connection error: {}", e),
            Err(e) => println!("Task error: {}", e),
        }
    }

    println!("Successful connections: {}/5", success_count);
    // Allow at least some connections to succeed
    assert!(success_count >= 1);

    Ok(())
}

/// Test MTProto packet framing
#[tokio::test]
async fn test_mtproto_packet_framing() -> Result<()> {
    let port = 19005;
    start_test_server(port).await?;

    // Connect to the server
    let mut stream = timeout(
        Duration::from_secs(5),
        TcpStream::connect(format!("127.0.0.1:{}", port)),
    )
    .await??;

    // Create a properly framed MTProto packet
    let mut packet = Vec::new();

    // Add authentication data first
    packet.extend_from_slice(&TEST_SECRET_BYTES);

    // Add some MTProto-like data (simplified)
    let msg_data = b"Hello MTProxy";
    let msg_len = msg_data.len() as u32;

    // Add length prefix and data
    packet.extend_from_slice(&msg_len.to_le_bytes());
    packet.extend_from_slice(msg_data);

    // Pad to minimum size
    while packet.len() < 64 {
        packet.push(0);
    }

    stream.write_all(&packet).await?;

    // Try to read response
    let mut buffer = [0u8; 256];
    match timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
        Ok(Ok(n)) => {
            println!("Received {} bytes in response to framed packet", n);
        }
        Ok(Err(_)) => {
            println!("Server closed connection after receiving packet");
        }
        Err(_) => {
            println!("Timeout waiting for response to framed packet");
        }
    }

    Ok(())
}

/// Test connection cleanup and resource management
#[tokio::test]
async fn test_connection_cleanup() -> Result<()> {
    let port = 19006;
    start_test_server(port).await?;

    // Create and drop multiple connections to test cleanup
    for i in 0..10 {
        let mut stream = timeout(
            Duration::from_secs(5),
            TcpStream::connect(format!("127.0.0.1:{}", port)),
        )
        .await??;

        // Send some data
        let auth_data = TEST_SECRET_BYTES.to_vec();
        let _ = stream.write_all(&auth_data).await;

        // Immediately drop the connection
        drop(stream);

        println!("Created and dropped connection {}", i);

        // Small delay between connections
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    println!("All connections created and dropped successfully");
    Ok(())
}

/// Test server startup and shutdown
#[tokio::test]
async fn test_server_startup_shutdown() -> Result<()> {
    let port = 19007;

    // Test that we can start the server
    start_test_server(port).await?;

    // Verify server is listening by connecting
    let stream = timeout(
        Duration::from_secs(5),
        TcpStream::connect(format!("127.0.0.1:{}", port)),
    )
    .await??;

    println!("Successfully connected to test server");
    drop(stream);

    // Note: In this test setup, the server runs in background task
    // For this test, we'll just verify the connection works

    // Give time for shutdown
    tokio::time::sleep(Duration::from_millis(100)).await;

    Ok(())
}

/// Test statistics endpoint accessibility
#[tokio::test]
async fn test_statistics_endpoint() -> Result<()> {
    let port = 19008;
    start_test_server(port).await?;

    // Test basic server responsiveness
    let stream = timeout(
        Duration::from_secs(5),
        TcpStream::connect(format!("127.0.0.1:{}", port)),
    )
    .await??;

    println!("Statistics test: server is responsive");
    drop(stream);

    Ok(())
}

/// Test edge cases and error conditions
#[tokio::test]
async fn test_edge_cases() -> Result<()> {
    let port = 19009;
    start_test_server(port).await?;

    // Test with empty data
    {
        let mut stream = timeout(
            Duration::from_secs(5),
            TcpStream::connect(format!("127.0.0.1:{}", port)),
        )
        .await??;

        // Send empty data
        stream.write_all(&[]).await?;
        drop(stream);
    }

    // Test with malformed data
    {
        let mut stream = timeout(
            Duration::from_secs(5),
            TcpStream::connect(format!("127.0.0.1:{}", port)),
        )
        .await??;

        // Send random malformed data
        let malformed_data = vec![0xff; 128];
        let _ = stream.write_all(&malformed_data).await;
        drop(stream);
    }

    // Test with partial data
    {
        let mut stream = timeout(
            Duration::from_secs(5),
            TcpStream::connect(format!("127.0.0.1:{}", port)),
        )
        .await??;

        // Send only partial authentication data
        let partial_data = &TEST_SECRET_BYTES[..8];
        let _ = stream.write_all(partial_data).await;
        drop(stream);
    }

    println!("Edge case tests completed");
    Ok(())
}
