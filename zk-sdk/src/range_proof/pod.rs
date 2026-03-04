//! Plain Old Data types for range proofs.

use {
    crate::{
        pod::{impl_from_bytes, impl_from_str},
        range_proof::*,
    },
    base64::{prelude::BASE64_STANDARD, Engine},
    bytemuck::{Pod, Zeroable},
    std::fmt,
};

/// The `RangeProof` type as a `Pod` restricted to proofs on 64-bit numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct PodRangeProofU64(pub(crate) [u8; RANGE_PROOF_U64_LEN]);

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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct PodRangeProofU128(pub(crate) [u8; RANGE_PROOF_U128_LEN]);

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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct PodRangeProofU256(pub(crate) [u8; RANGE_PROOF_U256_LEN]);

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
