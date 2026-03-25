use crate::config::ShardConfig;
use crate::server::{ShardResponder, ShardServer};
use std::ffi::CStr;
use std::net::SocketAddr;
use std::os::raw::{c_char, c_int};
use std::ptr;
use std::slice;
use std::str::FromStr;
use tokio::runtime::Runtime;

/// Opaque struct to hold the configuration on the Java side safely.
pub struct ShardConfigHandle(ShardConfig);

/// Creates a new Shard configuration.
///
/// # Arguments
/// * `addr_str` - Null-terminated C string containing "IP:PORT" (e.g., "127.0.0.1:8080").
/// * `psk_ptr` - Pointer to the 32-byte Pre-Shared Key.
/// * `psk_len` - Must be exactly 32.
///
/// # Returns
/// * Pointer to `ShardConfigHandle` on success.
/// * `NULL` on failure.
///
/// # Safety
/// The caller must ensure `addr_str` points to a valid, null-terminated C string,
/// and `psk_ptr` points to at least `psk_len` bytes of valid memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shard_create_config(
    addr_str: *const c_char,
    psk_ptr: *const u8,
    psk_len: usize,
) -> *mut ShardConfigHandle {
    if addr_str.is_null() || psk_ptr.is_null() || psk_len != 32 {
        return ptr::null_mut();
    }

    // Parse Address
    let c_str = unsafe { CStr::from_ptr(addr_str) };
    let Ok(addr_str_slice) = c_str.to_str() else {
        return ptr::null_mut();
    };

    let Ok(addr) = SocketAddr::from_str(addr_str_slice) else {
        return ptr::null_mut();
    };

    // Copy PSK
    let mut psk = [0u8; 32];
    let psk_slice = unsafe { slice::from_raw_parts(psk_ptr, 32) };
    psk.copy_from_slice(psk_slice);

    let config = ShardConfig::new(psk, addr);
    Box::into_raw(Box::new(ShardConfigHandle(config)))
}

/// Frees the configuration handle.
///
/// # Safety
/// The caller must ensure `ptr` is either null or a valid pointer returned by `shard_create_config`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shard_free_config(ptr: *mut ShardConfigHandle) {
    if !ptr.is_null() {
        unsafe {
            let _ = Box::from_raw(ptr);
        }
    }
}

/// Callback function type for receiving data.
/// `void on_packet(const uint8_t* data, size_t len);`
pub type DataCallback = extern "C" fn(*const u8, usize);

/// Starts the Shard server (Blocking).
///
/// # Arguments
/// * `config_ptr` - Valid pointer to `ShardConfigHandle`.
/// * `callback` - Function pointer to handle decrypted packets.
///
/// # Returns
/// * `0` on success (only returns if server stops gracefully).
/// * `-1` on initialization error.
/// * `-2` on runtime error.
///
/// # Safety
/// The caller must ensure `config_ptr` is a valid pointer to a `ShardConfigHandle`
/// created by `shard_create_config`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shard_start_server(
    config_ptr: *const ShardConfigHandle,
    callback: DataCallback,
) -> c_int {
    if config_ptr.is_null() {
        return -1;
    }

    let config = unsafe { &(*config_ptr).0 };

    // Validate config cloning if necessary, but Server takes ownership or clone internally.
    // Since ShardConfig is Clone, we can clone it to pass to the server.
    let config_clone = config.clone();

    let Ok(rt) = Runtime::new() else { return -2 };

    rt.block_on(async {
        let Ok(server) = ShardServer::bind(config_clone).await else {
            return -1;
        };

        // Wrap the C callback to be safe for Rust async loop
        // We ignore the responder in this basic FFI bridge for now.
        // A future update could expose the responder to Java.
        let callback_wrapper = move |data: Vec<u8>, _responder: ShardResponder| {
            callback(data.as_ptr(), data.len());
        };

        match server.listen(callback_wrapper).await {
            Ok(()) => 0,
            Err(_) => -2,
        }
    })
}
