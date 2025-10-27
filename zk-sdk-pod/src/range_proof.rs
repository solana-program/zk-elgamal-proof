//! Plain Old Data types for range proofs.

use {
    crate::{
        macros::{impl_from_bytes, impl_from_str},
        RISTRETTO_POINT_LEN, SCALAR_LEN,
    },
    base64::{prelude::BASE64_STANDARD, Engine},
    bytemuck::{Pod, Zeroable},
    std::fmt,
};

/// Byte length of a range proof excluding the inner-product proof component
pub const RANGE_PROOF_MODULO_INNER_PRODUCT_PROOF_LEN: usize =
    5 * RISTRETTO_POINT_LEN + 2 * SCALAR_LEN;

/// Byte length of an inner-product proof for a vector of length 64
pub const INNER_PRODUCT_PROOF_U64_LEN: usize = 448;

/// Byte length of a range proof for an unsigned 64-bit number
pub const RANGE_PROOF_U64_LEN: usize =
    INNER_PRODUCT_PROOF_U64_LEN + RANGE_PROOF_MODULO_INNER_PRODUCT_PROOF_LEN; // 672 bytes

/// Byte length of an inner-product proof for a vector of length 128
pub const INNER_PRODUCT_PROOF_U128_LEN: usize = 512;

/// Byte length of a range proof for an unsigned 128-bit number
pub const RANGE_PROOF_U128_LEN: usize =
    INNER_PRODUCT_PROOF_U128_LEN + RANGE_PROOF_MODULO_INNER_PRODUCT_PROOF_LEN; // 736 bytes

/// Byte length of an inner-product proof for a vector of length 256
pub const INNER_PRODUCT_PROOF_U256_LEN: usize = 576;

/// Byte length of a range proof for an unsigned 256-bit number
pub const RANGE_PROOF_U256_LEN: usize =
    INNER_PRODUCT_PROOF_U256_LEN + RANGE_PROOF_MODULO_INNER_PRODUCT_PROOF_LEN; // 800 bytes

/// The `RangeProof` type as a `Pod` restricted to proofs on 64-bit numbers.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct PodRangeProofU64(pub [u8; RANGE_PROOF_U64_LEN]);

const RANGE_PROOF_U64_MAX_BASE64_LEN: usize = 896;

impl fmt::Display for PodRangeProofU64 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.0))
    }
}

impl_from_str!(
    TYPE = PodRangeProofU64,
    BYTES_LEN = RANGE_PROOF_U64_LEN,
    BASE64_LEN = RANGE_PROOF_U64_MAX_BASE64_LEN
);

impl_from_bytes!(TYPE = PodRangeProofU64, BYTES_LEN = RANGE_PROOF_U64_LEN);

/// The `RangeProof` type as a `Pod` restricted to proofs on 128-bit numbers.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct PodRangeProofU128(pub [u8; RANGE_PROOF_U128_LEN]);

const RANGE_PROOF_U128_MAX_BASE64_LEN: usize = 984;

impl fmt::Display for PodRangeProofU128 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.0))
    }
}

impl_from_str!(
    TYPE = PodRangeProofU128,
    BYTES_LEN = RANGE_PROOF_U128_LEN,
    BASE64_LEN = RANGE_PROOF_U128_MAX_BASE64_LEN
);

impl_from_bytes!(TYPE = PodRangeProofU128, BYTES_LEN = RANGE_PROOF_U128_LEN);

/// The `RangeProof` type as a `Pod` restricted to proofs on 256-bit numbers.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct PodRangeProofU256(pub [u8; RANGE_PROOF_U256_LEN]);

const RANGE_PROOF_U256_MAX_BASE64_LEN: usize = 1068;

impl fmt::Display for PodRangeProofU256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.0))
    }
}

impl_from_str!(
    TYPE = PodRangeProofU256,
    BYTES_LEN = RANGE_PROOF_U256_LEN,
    BASE64_LEN = RANGE_PROOF_U256_MAX_BASE64_LEN
);

impl_from_bytes!(TYPE = PodRangeProofU256, BYTES_LEN = RANGE_PROOF_U256_LEN);

// The range proof pod types are wrappers for byte arrays, which are both `Pod` and `Zeroable`. However,
// the marker traits `bytemuck::Pod` and `bytemuck::Zeroable` can only be derived for power-of-two
// length byte arrays. Directly implement these traits for the range proof pod types.
unsafe impl Zeroable for PodRangeProofU64 {}
unsafe impl Pod for PodRangeProofU64 {}

unsafe impl Zeroable for PodRangeProofU128 {}
unsafe impl Pod for PodRangeProofU128 {}

unsafe impl Zeroable for PodRangeProofU256 {}
unsafe impl Pod for PodRangeProofU256 {}
