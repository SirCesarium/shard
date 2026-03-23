//! Shard SDK
//!
//! High-level software development kit for integrating Shard into applications.

/// Adds two integers.
///
/// # Examples
/// ```
/// let result = shard_sdk::add(1, 2);
/// assert_eq!(result, 3);
/// ```
#[must_use]
pub const fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
