use {
    crate::encryption::pedersen::PodPedersenCommitment,
    bytemuck_derive::{Pod, Zeroable},
};

pub mod batched_range_proof_u128;
pub mod batched_range_proof_u256;
pub mod batched_range_proof_u64;

pub use {
    batched_range_proof_u128::BatchedRangeProofU128Data,
    batched_range_proof_u256::BatchedRangeProofU256Data,
    batched_range_proof_u64::BatchedRangeProofU64Data,
};

/// The maximum number of Pedersen commitments that can be processed in a single batched range proof.
const MAX_COMMITMENTS: usize = 8;

/// The context data needed to verify a range-proof for a Pedersen committed value.
///
/// This struct holds the public information that a batched range proof certifies. It includes the
/// Pedersen commitments and their corresponding bit lengths. This context is shared by all
/// `VerifyBatchedRangeProof{N}` instructions.
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct BatchedRangeProofContext {
    pub commitments: [PodPedersenCommitment; MAX_COMMITMENTS],
    pub bit_lengths: [u8; MAX_COMMITMENTS],
}
