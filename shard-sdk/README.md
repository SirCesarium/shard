# Shard SDK

`shard-sdk` is a high-performance, asynchronous toolkit for building secure, low-latency applications using the **Shard 2.0 Protocol**. It provides a robust abstraction layer over the raw protocol, handling handshakes, session state, and bi-directional encrypted communication.

## Table of Contents
- [Architecture](#architecture)
- [Features](#features)
- [Rust Integration](#rust-integration)
- [Java Integration (Project Panama)](#java-integration-project-panama)
- [Security & Performance](#security--performance)
- [FFI Reference](#ffi-reference)

---

## Architecture

Shard 2.0 operates on a stateful **1-RTT Handshake** model over UDP:

```text
CLIENT                               SERVER
  |                                    |
  | [HandshakeInit]                    |
  | (E_pub_client, Auth: MasterPSK)    |
  |----------------------------------->| (Generates SessionKey)
  |                                    |
  | [HandshakeResponse]                |
  | (E_pub_server, Auth: MasterPSK)    |
  |<-----------------------------------|
  |                                    |
  | (Establishes SessionKey)           |
  |                                    |
  | [Data] (Crypted: SessionKey)       |
  |----------------------------------->|
  |                                    |
  | [Data] (Crypted: SessionKey)       |
  |<-----------------------------------| (Bi-directional Response)
```

## Features

- **Perfect Forward Secrecy (PFS):** Unique X25519 session keys ensure that compromised master keys cannot decrypt historical traffic.
- **Bi-directional Communication:** Full Request-Response support with independent sequence ID tracking.
- **Stateful Management:** Transparent peer tracking using `dashmap` for lock-free concurrency.
- **Zero-Copy Performance:** Uses `zerocopy` for header parsing and in-place decryption.
- **Automatic Replay Protection:** Monotonic sequence validation per session.

---

## Rust Integration

### Building a Server
The server uses a callback-based listener that provides a `ShardResponder` for sending data back to clients.

```rust
use shard_sdk::server::{ShardServer, ShardResponder};
use shard_sdk::config::ShardConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // SECURITY: Use 'shard keygen' to generate a real Master PSK. 
    // Never use a hardcoded zero-key in production.
    let psk = [0u8; 32]; 
    let addr = "0.0.0.0:3000".parse()?;
    let config = ShardConfig::new(psk, addr);
    let server = ShardServer::bind(config).await?;

    server.listen(|payload, responder| {
        let msg = String::from_utf8_lossy(&payload);
        println!("Received: {}", msg);

        // Send response back
        tokio::spawn(async move {
            let _ = responder.send(b"Command Received").await;
        });
    }).await?;

    Ok(())
}
```


### Basic Client
The `ShardSession` handles the handshake automatically upon creation.

```rust
use shard_sdk::session::ShardSession;
use shard_sdk::config::ShardConfig;
use std::time::Duration;

async fn run_client() -> Result<(), Box<dyn std::error::Error>> {
    let config = ShardConfig::new([0u8; 32], "127.0.0.1:3000".parse()?);
    let session = ShardSession::new(config).await?;

    // Send data
    session.send_message(b"status").await?;

    // Receive response
    let resp = session.inner_client().receive(Duration::from_secs(2)).await?;
    println!("Server said: {}", String::from_utf8_lossy(&resp));
    
    Ok(())
}
```

---

## Java Integration (Project Panama)

Shard provides near-native performance for Java 21+ using the Foreign Function & Memory (FFM) API.

### Native Access
To use the SDK in Java, you must provide the compiled `.so`, `.dll`, or `.dylib` and run with:
`--enable-preview --enable-native-access=ALL-UNNAMED`

### Gradle Setup
```groovy
tasks.withType(JavaExec).configureEach {
    jvmArgs += ["--enable-preview", "--enable-native-access=ALL-UNNAMED", "-Djava.library.path=./libs"]
}
```

---

## Security & Performance

### Threat Model
- **Active MITM:** Protected by MasterPSK authentication during Handshake.
- **Passive Sniffing:** Protected by X25519 ECDH and ChaCha20-Poly1305.
- **Replay Attacks:** Protected by monotonic `SEQ_ID` tracking per session.
- **DoS:** Handshake Init frames are processed before expensive crypto if valid headers are present.

### Memory Safety (FFI)
When calling from Java/C:
1. `shard_create_config` allocates memory on the Rust heap.
2. You MUST call `shard_free_config` to avoid memory leaks.
3. Callbacks receive a pointer to Rust-managed memory. This memory is only valid for the duration of the callback. **Do not store the pointer.**

---

## FFI Reference

| Function | Description | Safety |
|----------|-------------|--------|
| `shard_create_config` | Allocates a new Shard configuration. | Unsafe (Raw pointers) |
| `shard_free_config` | Frees configuration memory. | Unsafe (Must match pointer) |
| `shard_start_server` | Blocks thread and runs server loop. | Unsafe (Callback must be thread-safe) |

## License
Licensed under the MIT License.
