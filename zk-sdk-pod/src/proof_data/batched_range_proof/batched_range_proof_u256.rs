use {
    crate::{
        proof_data::batched_range_proof::BatchedRangeProofContext, range_proof::PodRangeProofU256,
    },
    bytemuck_derive::{Pod, Zeroable},
};

/// The instruction data that is needed for the
/// `ProofInstruction::BatchedRangeProofU256Data` instruction.
///
/// It includes the cryptographic proof as well as the context data information needed to verify
/// the proof.
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct BatchedRangeProofU256Data {
    /// The context data for a batched range proof
    pub context: BatchedRangeProofContext,

    /// The batched range proof
    pub proof: PodRangeProofU256,
}
