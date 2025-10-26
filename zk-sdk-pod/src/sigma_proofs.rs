//! Plain Old Data types for sigma proofs.

use {
    crate::macros::{impl_from_bytes, impl_from_str},
    base64::{prelude::BASE64_STANDARD, Engine},
    bytemuck::{Pod, Zeroable},
    std::fmt,
};

/// Byte length of a ciphertext-commitment equality proof
pub const CIPHERTEXT_COMMITMENT_EQUALITY_PROOF_LEN: usize = 192;

/// Byte length of a ciphertext-ciphertext equality proof
pub const CIPHERTEXT_CIPHERTEXT_EQUALITY_PROOF_LEN: usize = 224;

/// Byte length of a grouped ciphertext for 2 handles validity proof
pub const GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY_PROOF_LEN: usize = 160;

/// Byte length of a grouped ciphertext for 3 handles validity proof
pub const GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_PROOF_LEN: usize = 192;

/// Byte length of a batched grouped ciphertext for 2 handles validity proof
pub const BATCHED_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY_PROOF_LEN: usize = 160;

/// Byte length of a batched grouped ciphertext for 3 handles validity proof
pub const BATCHED_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_PROOF_LEN: usize = 192;

/// Byte length of a zero-ciphertext proof
pub const ZERO_CIPHERTEXT_PROOF_LEN: usize = 96;

/// Byte length of a percentage with cap proof
pub const PERCENTAGE_WITH_CAP_PROOF_LEN: usize = 256;

/// Byte length of a public key validity proof
pub const PUBKEY_VALIDITY_PROOF_LEN: usize = 64;

/// The `CiphertextCommitmentEqualityProof` type as a `Pod`.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct PodCiphertextCommitmentEqualityProof(pub [u8; CIPHERTEXT_COMMITMENT_EQUALITY_PROOF_LEN]);

const CIPHERTEXT_COMMITMENT_EQUALITY_PROOF_MAX_BASE64_LEN: usize = 256;

impl fmt::Display for PodCiphertextCommitmentEqualityProof {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.0))
    }
}

impl_from_str!(
    TYPE = PodCiphertextCommitmentEqualityProof,
    BYTES_LEN = CIPHERTEXT_COMMITMENT_EQUALITY_PROOF_LEN,
    BASE64_LEN = CIPHERTEXT_COMMITMENT_EQUALITY_PROOF_MAX_BASE64_LEN
);

impl_from_bytes!(
    TYPE = PodCiphertextCommitmentEqualityProof,
    BYTES_LEN = CIPHERTEXT_COMMITMENT_EQUALITY_PROOF_LEN
);

/// The `CiphertextCiphertextEqualityProof` type as a `Pod`.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct PodCiphertextCiphertextEqualityProof(pub [u8; CIPHERTEXT_CIPHERTEXT_EQUALITY_PROOF_LEN]);

const CIPHERTEXT_CIPHERTEXT_EQUALITY_PROOF_MAX_BASE64_LEN: usize = 300;

impl fmt::Display for PodCiphertextCiphertextEqualityProof {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.0))
    }
}

impl_from_str!(
    TYPE = PodCiphertextCiphertextEqualityProof,
    BYTES_LEN = CIPHERTEXT_CIPHERTEXT_EQUALITY_PROOF_LEN,
    BASE64_LEN = CIPHERTEXT_CIPHERTEXT_EQUALITY_PROOF_MAX_BASE64_LEN
);

impl_from_bytes!(
    TYPE = PodCiphertextCiphertextEqualityProof,
    BYTES_LEN = CIPHERTEXT_CIPHERTEXT_EQUALITY_PROOF_LEN
);

/// The `GroupedCiphertext2HandlesValidityProof` type as a `Pod`.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct PodGroupedCiphertext2HandlesValidityProof(
    pub [u8; GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY_PROOF_LEN],
);

const GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY_PROOF_MAX_BASE64_LEN: usize = 216;

impl fmt::Display for PodGroupedCiphertext2HandlesValidityProof {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.0))
    }
}

impl_from_str!(
    TYPE = PodGroupedCiphertext2HandlesValidityProof,
    BYTES_LEN = GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY_PROOF_LEN,
    BASE64_LEN = GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY_PROOF_MAX_BASE64_LEN
);

impl_from_bytes!(
    TYPE = PodGroupedCiphertext2HandlesValidityProof,
    BYTES_LEN = GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY_PROOF_LEN
);

/// The `GroupedCiphertext3HandlesValidityProof` type as a `Pod`.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct PodGroupedCiphertext3HandlesValidityProof(
    pub [u8; GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_PROOF_LEN],
);

const GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_PROOF_MAX_BASE64_LEN: usize = 256;

impl fmt::Display for PodGroupedCiphertext3HandlesValidityProof {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.0))
    }
}

impl_from_str!(
    TYPE = PodGroupedCiphertext3HandlesValidityProof,
    BYTES_LEN = GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_PROOF_LEN,
    BASE64_LEN = GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_PROOF_MAX_BASE64_LEN
);

impl_from_bytes!(
    TYPE = PodGroupedCiphertext3HandlesValidityProof,
    BYTES_LEN = GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_PROOF_LEN
);

/// The `BatchedGroupedCiphertext2HandlesValidityProof` type as a `Pod`.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct PodBatchedGroupedCiphertext2HandlesValidityProof(
    pub [u8; BATCHED_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY_PROOF_LEN],
);

const BATCHED_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY_PROOF_MAX_BASE64_LEN: usize = 216;

impl fmt::Display for PodBatchedGroupedCiphertext2HandlesValidityProof {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.0))
    }
}

impl_from_str!(
    TYPE = PodBatchedGroupedCiphertext2HandlesValidityProof,
    BYTES_LEN = BATCHED_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY_PROOF_LEN,
    BASE64_LEN = BATCHED_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY_PROOF_MAX_BASE64_LEN
);

impl_from_bytes!(
    TYPE = PodBatchedGroupedCiphertext2HandlesValidityProof,
    BYTES_LEN = BATCHED_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY_PROOF_LEN
);

/// The `BatchedGroupedCiphertext3HandlesValidityProof` type as a `Pod`.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct PodBatchedGroupedCiphertext3HandlesValidityProof(
    pub [u8; BATCHED_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_PROOF_LEN],
);

const BATCHED_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_PROOF_MAX_BASE64_LEN: usize = 256;

impl fmt::Display for PodBatchedGroupedCiphertext3HandlesValidityProof {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.0))
    }
}

impl_from_str!(
    TYPE = PodBatchedGroupedCiphertext3HandlesValidityProof,
    BYTES_LEN = BATCHED_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_PROOF_LEN,
    BASE64_LEN = BATCHED_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_PROOF_MAX_BASE64_LEN
);

impl_from_bytes!(
    TYPE = PodBatchedGroupedCiphertext3HandlesValidityProof,
    BYTES_LEN = BATCHED_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_PROOF_LEN
);

/// The `ZeroCiphertextProof` type as a `Pod`.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct PodZeroCiphertextProof(pub [u8; ZERO_CIPHERTEXT_PROOF_LEN]);

const ZERO_CIPHERTEXT_PROOF_MAX_BASE64_LEN: usize = 128;

impl fmt::Display for PodZeroCiphertextProof {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.0))
    }
}

impl_from_str!(
    TYPE = PodZeroCiphertextProof,
    BYTES_LEN = ZERO_CIPHERTEXT_PROOF_LEN,
    BASE64_LEN = ZERO_CIPHERTEXT_PROOF_MAX_BASE64_LEN
);

impl_from_bytes!(
    TYPE = PodZeroCiphertextProof,
    BYTES_LEN = ZERO_CIPHERTEXT_PROOF_LEN
);

/// The `PercentageWithCapProof` type as a `Pod`.
#[derive(Clone, Copy, bytemuck_derive::Pod, bytemuck_derive::Zeroable)]
#[repr(transparent)]
pub struct PodPercentageWithCapProof(pub [u8; PERCENTAGE_WITH_CAP_PROOF_LEN]);

const PERCENTAGE_WITH_CAP_PROOF_MAX_BASE64_LEN: usize = 344;

impl fmt::Display for PodPercentageWithCapProof {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.0))
    }
}

impl_from_str!(
    TYPE = PodPercentageWithCapProof,
    BYTES_LEN = PERCENTAGE_WITH_CAP_PROOF_LEN,
    BASE64_LEN = PERCENTAGE_WITH_CAP_PROOF_MAX_BASE64_LEN
);

impl_from_bytes!(
    TYPE = PodPercentageWithCapProof,
    BYTES_LEN = PERCENTAGE_WITH_CAP_PROOF_LEN
);

/// The `PubkeyValidityProof` type as a `Pod`.
#[derive(Clone, Copy, bytemuck_derive::Pod, bytemuck_derive::Zeroable)]
#[repr(transparent)]
pub struct PodPubkeyValidityProof(pub [u8; PUBKEY_VALIDITY_PROOF_LEN]);

const PUBKEY_VALIDITY_PROOF_MAX_BASE64_LEN: usize = 88;

impl fmt::Display for PodPubkeyValidityProof {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.0))
    }
}

impl_from_str!(
    TYPE = PodPubkeyValidityProof,
    BYTES_LEN = PUBKEY_VALIDITY_PROOF_LEN,
    BASE64_LEN = PUBKEY_VALIDITY_PROOF_MAX_BASE64_LEN
);

impl_from_bytes!(
    TYPE = PodPubkeyValidityProof,
    BYTES_LEN = PUBKEY_VALIDITY_PROOF_LEN
);

// The sigma proof pod types are wrappers for byte arrays, which are both `Pod` and `Zeroable`. However,
// the marker traits `bytemuck::Pod` and `bytemuck::Zeroable` can only be derived for power-of-two
// length byte arrays. Directly implement these traits for the sigma proof pod types.
unsafe impl Zeroable for PodCiphertextCommitmentEqualityProof {}
unsafe impl Pod for PodCiphertextCommitmentEqualityProof {}

unsafe impl Zeroable for PodCiphertextCiphertextEqualityProof {}
unsafe impl Pod for PodCiphertextCiphertextEqualityProof {}

unsafe impl Zeroable for PodGroupedCiphertext2HandlesValidityProof {}
unsafe impl Pod for PodGroupedCiphertext2HandlesValidityProof {}

unsafe impl Zeroable for PodGroupedCiphertext3HandlesValidityProof {}
unsafe impl Pod for PodGroupedCiphertext3HandlesValidityProof {}

unsafe impl Zeroable for PodBatchedGroupedCiphertext2HandlesValidityProof {}
unsafe impl Pod for PodBatchedGroupedCiphertext2HandlesValidityProof {}

unsafe impl Zeroable for PodBatchedGroupedCiphertext3HandlesValidityProof {}
unsafe impl Pod for PodBatchedGroupedCiphertext3HandlesValidityProof {}

unsafe impl Zeroable for PodZeroCiphertextProof {}
unsafe impl Pod for PodZeroCiphertextProof {}
