//! Plain Old Data type for the Pedersen commitment scheme.

use {
    crate::{
        encryption::PEDERSEN_COMMITMENT_LEN,
        macros::{impl_from_bytes, impl_from_str},
    },
    base64::{prelude::BASE64_STANDARD, Engine},
    bytemuck_derive::{Pod, Zeroable},
    std::fmt,
};

/// Maximum length of a base64 encoded ElGamal public key
const PEDERSEN_COMMITMENT_MAX_BASE64_LEN: usize = 44;

/// The `PedersenCommitment` type as a `Pod`.
#[derive(Clone, Copy, Default, Pod, Zeroable, PartialEq, Eq)]
#[repr(transparent)]
pub struct PodPedersenCommitment(pub [u8; PEDERSEN_COMMITMENT_LEN]);

impl fmt::Debug for PodPedersenCommitment {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl fmt::Display for PodPedersenCommitment {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.0))
    }
}

impl_from_str!(
    TYPE = PodPedersenCommitment,
    BYTES_LEN = PEDERSEN_COMMITMENT_LEN,
    BASE64_LEN = PEDERSEN_COMMITMENT_MAX_BASE64_LEN
);

impl_from_bytes!(
    TYPE = PodPedersenCommitment,
    BYTES_LEN = PEDERSEN_COMMITMENT_LEN
);
