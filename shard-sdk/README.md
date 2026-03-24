# Shard SDK

`shard-sdk` is the high-level asynchronous toolkit for building secure, low-latency applications using the Shard protocol. It supports both native Rust development and modern Java integration via **Project Panama**.

## Features

- **Asynchronous I/O:** Built on top of `tokio` for high-concurrency UDP processing.
- **Automatic Key Rotation:** Handles the complexity of HKDF key derivation and sequence tracking internally.
- **Multi-Language Support:** First-class C-ABI exports for Java 22+, C++, and Python.
- **Stateless Reliability:** Uses monotonic Unix nanoseconds for initial sequence IDs, ensuring integrity across restarts without persistent state.

## Rust Usage

### Installation
Add to your `Cargo.toml`:
```toml
[dependencies]
shard-sdk = "0.1.1"
tokio = { version = "1.0", features = ["full"] }
```

### Building a Server
```rust
use shard_sdk::server::ShardServer;
use shard_sdk::config::ShardConfig;

#[tokio::main]
async fn main() -> tokio::io::Result<()> {
    let psk = [0u8; 32]; // Replace with real 32-byte key
    let addr = "0.0.0.0:3000".parse().unwrap();
    let config = ShardConfig::new(psk, addr);

    let server = ShardServer::bind(config).await?;
    println!("Shard server listening on {}", addr);

    server.listen(|payload| {
        println!("Received decrypted payload: {:?}", payload);
    }).await
}
```

### Building a Client
```rust
use shard_sdk::client::ShardClient;
use shard_sdk::config::ShardConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let psk = [0u8; 32];
    let config = ShardConfig::new(psk, "127.0.0.1:3000".parse()?);

    let client = ShardClient::connect(config).await?;
    client.send(b"Hello Shard!").await?;
    Ok(())
}
```

---

## Java Integration (Project Panama)

Shard supports **Java 22+** directly via the Foreign Function & Memory API (Panama), providing near-native performance without the overhead of JNI.

### Prerequisites
1.  Download the `libshard_sdk` for your platform (.dll, .so, or .dylib).
2.  Java 22 or higher.

### Gradle Configuration
Ensure your native library is in the library path:
```groovy
tasks.withType(JavaExec).configureEach {
    jvmArgs += ["--enable-native-access=ALL-UNNAMED", "-Djava.library.path=./libs"]
}
```

### Java Example (Using `java.lang.foreign`)

```java
import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;

public class ShardJava {
    public static void main(String[] args) throws Throwable {
        SymbolLookup lib = SymbolLookup.libraryLookup("shard_sdk", Arena.global());
        Linker linker = Linker.nativeLinker();

        // 1. Define C Functions
        MethodHandle createConfig = linker.downcallHandle(
            lib.find("shard_create_config").get(),
            FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG)
        );

        // 2. Start Server with Callback
        // Refer to the shard-sdk/src/ffi.rs for detailed ABI signatures.
        System.out.println("Shard Native Bridge Initialized");
    }
}
```

*Note: For a full Java wrapper, it is recommended to use `jextract` on the provided headers.*

## License
MIT License.
