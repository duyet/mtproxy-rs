# MTProxy-RS Test Suite

This directory contains the test suite for MTProxy-RS, organized into different types of tests for better maintainability and clarity.

## Test Organization

### 1. `integration_client_connections.rs` - Client Integration Tests
**Purpose**: Full integration tests that simulate real client connections to the MTProxy server.

**What it tests**:
- Client authentication with valid/invalid secrets
- Random padding mode (dd prefix) support
- Multiple concurrent connections
- MTProto packet framing
- Connection cleanup and resource management
- Server startup/shutdown lifecycle
- Statistics endpoint functionality
- Edge cases and error conditions

**Test Ports**: Uses ports 19001-19009 to avoid conflicts
**Requirements**: Requires starting actual MTProxy server instances

### 2. `unit_functionality.rs` - Unit-Style Functionality Tests
**Purpose**: Unit-style tests that verify individual components and functionality without requiring full server setup.

**What it tests**:
- Hex secret parsing and validation
- Configuration parsing utilities
- Port validation logic
- Command line argument simulation
- Connection state management
- Basic cryptographic operations
- Error handling patterns
- Transport layer header parsing
- MTProto packet structure validation
- Async operation patterns

**Requirements**: No external dependencies, fast execution

## Running Tests

### Run All Tests
```bash
cargo test
```

### Run Specific Test Suites
```bash
# Run only integration tests (client connections)
cargo test --test integration_client_connections

# Run only unit functionality tests
cargo test --test unit_functionality
```

### Run Individual Tests
```bash
# Run a specific integration test
cargo test --test integration_client_connections test_client_connection_valid_secret

# Run a specific unit test
cargo test --test unit_functionality test_hex_secret_parsing
```

### Debug Mode
```bash
# Run with debug output
RUST_LOG=debug cargo test --test integration_client_connections

# Run with nocapture to see println! output
cargo test --test unit_functionality -- --nocapture
```

## Test Configuration

### Integration Test Settings
- **Test Secrets**: Uses `deadbeefcafebabe1234567890abcdef` as the standard test secret
- **Random Padding**: Tests both normal and `dd`-prefixed secrets
- **Ports**: Each test uses a unique port (19001-19009) to run in parallel
- **Timeouts**: Most operations have 5-second timeouts for robustness
- **Stats Port**: Uses port 18888 to avoid conflicts with main application

### Unit Test Patterns
- **No I/O**: Pure computational tests that don't require network or file operations
- **Fast Execution**: Tests should complete in milliseconds
- **Self-Contained**: Each test is independent and doesn't rely on external state
- **Error Coverage**: Tests both success and failure scenarios

## Adding New Tests

### For Integration Tests
Add to `integration_client_connections.rs` when testing:
- Real client-server interactions
- Network protocol behavior
- End-to-end authentication flows
- Performance under load
- Resource management

### For Unit Tests
Add to `unit_functionality.rs` when testing:
- Individual function behavior
- Data validation logic
- Algorithm implementations
- Error handling paths
- Configuration parsing

## Test Data

### Secrets Used in Tests
- **Standard Secret**: `deadbeefcafebabe1234567890abcdef`
- **Random Padding Secret**: `dddeadbeefcafebabe1234567890abcd` (dd prefix)
- **Invalid Secret**: `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` (invalid format)

### Test Server Configuration
The integration tests create minimal test configurations with:
- Default cluster ID: 2
- Test Telegram servers: 149.154.161.144:8888, 91.108.4.204:8888
- Connection limits: 100 concurrent connections
- Worker count: 1 (for testing simplicity)

## Troubleshooting

### Common Issues

1. **Port Already in Use**
   - Integration tests use unique ports to avoid conflicts
   - If tests fail due to port conflicts, check for other running instances

2. **Connection Timeouts**
   - Integration tests have built-in timeouts
   - Failures may indicate server startup issues or resource constraints

3. **Authentication Failures**
   - Verify that the dd-prefix handling is working correctly
   - Check secret validation logic in the main codebase

4. **Resource Leaks**
   - Connection cleanup tests verify proper resource management
   - Failed cleanup tests may indicate memory or file descriptor leaks

### Performance Considerations

- Integration tests are inherently slower due to actual network operations
- Unit tests should complete in under 100ms each
- Parallel test execution is supported for both test types
- Use `cargo test --jobs 1` if experiencing resource contention

## Coverage

The test suite aims for comprehensive coverage of:
- ✅ Core authentication flows
- ✅ Random padding mode support
- ✅ Configuration parsing
- ✅ Error handling
- ✅ Concurrent connections
- ✅ Resource management
- ✅ Protocol validation

For coverage reports, use:
```bash
cargo install cargo-tarpaulin
cargo tarpaulin --tests
``` 