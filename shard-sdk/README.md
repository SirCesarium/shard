# Shard SDK

`shard-sdk` is the high-level asynchronous toolkit for building secure, low-latency applications using the **Shard 2.0 Protocol**. It supports both native Rust development and modern Java integration via **Project Panama**.

## Features

- **Asynchronous Handshake:** Built-in X25519 1-RTT handshake logic for session key establishment.
- **Perfect Forward Secrecy (PFS):** Unique keys per session ensure past traffic remains secure.
- **Stateful Session Management:** High-performance concurrent session tracking using `dashmap`.
- **Multi-Language Support:** First-class C-ABI exports for Java 22+, C++, and Python.

## Rust Usage

### Installation
Add to your `Cargo.toml`:
```toml
[dependencies]
shard-sdk = "0.2.0"
tokio = { version = "1.0", features = ["full"] }
```

### Building a Server
```rust
use shard_sdk::server::ShardServer;
use shard_sdk::config::ShardConfig;

#[tokio::main]
async fn main() -> tokio::io::Result<()> {
    let psk = [0u8; 32]; // 32-byte Master PSK
    let addr = "0.0.0.0:3000".parse().unwrap();
    let config = ShardConfig::new(psk, addr);

    let server = ShardServer::bind(config).await?;
    println!("Shard 2.0 server listening on {}", addr);

    server.listen(|payload| {
        println!("Received decrypted payload: {:?}", payload);
    }).await
}
```

### Building a Client
```rust
use shard_sdk::session::ShardSession;
use shard_sdk::config::ShardConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let psk = [0u8; 32];
    let config = ShardConfig::new(psk, "127.0.0.1:3000".parse()?);

    // Performs handshake automatically
    let session = ShardSession::new(config).await?;
    session.send_message(b"Hello Shard 2.0!").await?;
    Ok(())
}
```

---

## Java Integration (Project Panama)

Shard 2.0 supports **Java 22+** (and Java 21 Preview) via the Foreign Function & Memory API (Panama).

### Prerequisites
1.  Download the `libshard_sdk` for your platform.
2.  Java 21 or higher.

### Java Example (Using `java.lang.foreign`)

```java
// Handshake and session management is handled internally by the native SDK
SymbolLookup lib = SymbolLookup.libraryLookup("shard_sdk", Arena.global());
// ... call shard_create_config and shard_start_server as usual
```

*Refer to the `ffi` module in `shard-sdk/src/ffi.rs` for the complete C-ABI.*

## License
MIT License.
