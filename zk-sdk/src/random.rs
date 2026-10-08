//! Internal randomness helpers that do not depend on random number generator traits.

use {solana_ed25519::scalar::Scalar, std::mem::MaybeUninit, zeroize::Zeroizing};

/// Fills a buffer with cryptographically secure randomness and returns the initialized bytes.
///
/// Panics if the operating system's entropy source fails.
pub(crate) fn fill_random_bytes<const N: usize>(bytes: &mut [MaybeUninit<u8>; N]) -> &mut [u8; N] {
    getrandom::getrandom_uninit(bytes)
        .expect("secure randomness unavailable")
        .try_into()
        .expect("getrandom returns a slice with the same length")
}

/// Samples a scalar with the same 64-byte reduction as `Scalar::random`.
pub(crate) fn random_scalar() -> Scalar {
    let mut bytes = Zeroizing::new([MaybeUninit::uninit(); 64]);
    Scalar::from_bytes_mod_order_wide(fill_random_bytes(&mut bytes))
}
