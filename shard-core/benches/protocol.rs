//! Shard Protocol Core Benchmarks
//!
//! Measures the performance of critical path operations:
//! - Key Derivation (HKDF)
//! - AEAD Encryption/Decryption
//! - Zero-Copy Header Parsing

#![allow(clippy::pedantic, clippy::nursery, missing_docs)] // Relax clippy for benchmarks

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use shard_core::consts::VERSION;
use shard_core::crypto::hkdf::derive_session_key;
use shard_core::crypto::{decrypt_frame_payload, encrypt_frame_payload};
use shard_core::frame::{ShardFrame, ShardHeader};
use zerocopy::big_endian::{U32, U64};

/// Main benchmark suite for the Shard protocol.
fn bench_protocol(c: &mut Criterion) {
    let master_psk = [0u8; 32];
    let payload = b"shard-benchmark-payload-1024-bytes-simulated-command-data".to_vec();
    let mut header = ShardHeader {
        version: VERSION,
        frame_type: 0,
        sequence_id: U64::new(1),
        timestamp: U64::new(1774379752),
        nonce: [0u8; 12],
        payload_len: U32::new(payload.len() as u32),
    };

    // 1. HKDF Performance (Key Derivation)
    c.bench_function("hkdf_derive_session_key", |b| {
        b.iter(|| derive_session_key(black_box(&master_psk), black_box(1)))
    });

    // 2. Encryption Performance
    c.bench_function("aead_encrypt_payload", |b| {
        let mut p = payload.clone();
        b.iter(|| {
            let _ = encrypt_frame_payload(
                black_box(&master_psk),
                black_box(&mut header),
                black_box(&mut p),
            );
        })
    });

    // 3. Decryption Performance
    if let Ok(tag) = encrypt_frame_payload(&master_psk, &mut header, &mut payload.clone()) {
        c.bench_function("aead_decrypt_payload", |b| {
            let mut p = payload.clone();
            b.iter(|| {
                let _ = decrypt_frame_payload(
                    black_box(&master_psk),
                    black_box(&header),
                    black_box(&mut p),
                    black_box(&tag),
                );
            })
        });
    }

    // 4. Zero-Copy Header Parsing
    let raw_header = zerocopy::IntoBytes::as_bytes(&header);
    c.bench_function("zerocopy_header_parsing", |b| {
        b.iter(|| {
            let _ = ShardFrame::from_bytes(black_box(raw_header));
        })
    });
}

criterion_group!(benches, bench_protocol);
criterion_main!(benches);
