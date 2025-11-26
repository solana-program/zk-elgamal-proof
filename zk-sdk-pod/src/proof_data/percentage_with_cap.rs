use {
    crate::{
        encryption::pedersen::PodPedersenCommitment, num::PodU64,
        sigma_proofs::PodPercentageWithCapProof,
    },
    bytemuck_derive::{Pod, Zeroable},
};

/// The instruction data that is needed for the `ProofInstruction::VerifyPercentageWithCap`
/// instruction.
///
/// It includes the cryptographic proof as well as the context data information needed to verify
/// the proof.
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct PercentageWithCapProofData {
    pub context: PercentageWithCapProofContext,

    pub proof: PodPercentageWithCapProof,
}

/// The context data needed to verify a percentage-with-cap proof.
///
/// We refer to [`ZK ElGamal proof`] for the formal details on how the percentage-with-cap proof is
/// computed.
///
/// [`ZK ElGamal proof`]: https://docs.solanalabs.com/runtime/zk-token-proof
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct PercentageWithCapProofContext {
    /// The Pedersen commitment to the percentage amount.
    pub percentage_commitment: PodPedersenCommitment,

    /// The Pedersen commitment to the delta amount.
    pub delta_commitment: PodPedersenCommitment,

    /// The Pedersen commitment to the claimed amount.
    pub claimed_commitment: PodPedersenCommitment,

    /// The maximum cap bound.
    pub max_value: PodU64,
}
