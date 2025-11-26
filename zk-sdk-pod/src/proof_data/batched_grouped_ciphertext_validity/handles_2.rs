use {
    crate::{
        encryption::{
            elgamal::PodElGamalPubkey, grouped_elgamal::PodGroupedElGamalCiphertext2Handles,
        },
        sigma_proofs::PodBatchedGroupedCiphertext2HandlesValidityProof,
    },
    bytemuck_derive::{Pod, Zeroable},
};

/// The instruction data that is needed for the
/// `ProofInstruction::VerifyBatchedGroupedCiphertextValidity` instruction.
///
/// It includes the cryptographic proof as well as the context data information needed to verify
/// the proof.
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct BatchedGroupedCiphertext2HandlesValidityProofData {
    pub context: BatchedGroupedCiphertext2HandlesValidityProofContext,

    pub proof: PodBatchedGroupedCiphertext2HandlesValidityProof,
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct BatchedGroupedCiphertext2HandlesValidityProofContext {
    pub first_pubkey: PodElGamalPubkey, // 32 bytes

    pub second_pubkey: PodElGamalPubkey, // 32 bytes

    pub grouped_ciphertext_lo: PodGroupedElGamalCiphertext2Handles, // 96 bytes

    pub grouped_ciphertext_hi: PodGroupedElGamalCiphertext2Handles, // 96 bytes
}
