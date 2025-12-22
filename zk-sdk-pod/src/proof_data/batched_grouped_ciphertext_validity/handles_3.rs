use {
    crate::{
        encryption::{
            elgamal::PodElGamalPubkey, grouped_elgamal::PodGroupedElGamalCiphertext3Handles,
        },
        sigma_proofs::PodBatchedGroupedCiphertext3HandlesValidityProof,
    },
    bytemuck_derive::{Pod, Zeroable},
};

/// The instruction data that is needed for the
/// `ProofInstruction::VerifyBatchedGroupedCiphertext3HandlesValidity` instruction.
///
/// It includes the cryptographic proof as well as the context data information needed to verify
/// the proof.
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct BatchedGroupedCiphertext3HandlesValidityProofData {
    pub context: BatchedGroupedCiphertext3HandlesValidityProofContext,

    pub proof: PodBatchedGroupedCiphertext3HandlesValidityProof,
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct BatchedGroupedCiphertext3HandlesValidityProofContext {
    pub first_pubkey: PodElGamalPubkey, // 32 bytes

    pub second_pubkey: PodElGamalPubkey, // 32 bytes

    pub third_pubkey: PodElGamalPubkey, // 32 bytes

    pub grouped_ciphertext_lo: PodGroupedElGamalCiphertext3Handles, // 128 bytes

    pub grouped_ciphertext_hi: PodGroupedElGamalCiphertext3Handles, // 128 bytes
}
