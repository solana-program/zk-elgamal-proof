//! Internal randomness helpers that do not depend on random number generator traits.

use {curve25519_dalek::scalar::Scalar, zeroize::Zeroizing};

/// Fills a buffer with cryptographically secure randomness.
///
/// Panics if the operating system's entropy source fails.
pub(crate) fn fill_random_bytes(bytes: &mut [u8]) {
    getrandom::getrandom(bytes).expect("secure randomness unavailable");
}

/// Samples a scalar with the same 64-byte reduction as `Scalar::random`.
pub(crate) fn random_scalar() -> Scalar {
    let mut bytes = Zeroizing::new([0u8; 64]);
    fill_random_bytes(bytes.as_mut_slice());
    Scalar::from_bytes_mod_order_wide(&bytes)
}
