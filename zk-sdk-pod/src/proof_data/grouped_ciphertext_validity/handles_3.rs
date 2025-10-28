use {
    crate::{
        encryption::{
            elgamal::PodElGamalPubkey, grouped_elgamal::PodGroupedElGamalCiphertext3Handles,
        },
        sigma_proofs::PodGroupedCiphertext3HandlesValidityProof,
    },
    bytemuck_derive::{Pod, Zeroable},
};

/// The instruction data that is needed for the
/// `ProofInstruction::VerifyGroupedCiphertext3HandlesValidity` instruction.
///
/// It includes the cryptographic proof as well as the context data information needed to verify
/// the proof.
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct GroupedCiphertext3HandlesValidityProofData {
    pub context: GroupedCiphertext3HandlesValidityProofContext,

    pub proof: PodGroupedCiphertext3HandlesValidityProof,
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct GroupedCiphertext3HandlesValidityProofContext {
    pub first_pubkey: PodElGamalPubkey, // 32 bytes

    pub second_pubkey: PodElGamalPubkey, // 32 bytes

    pub third_pubkey: PodElGamalPubkey, // 32 bytes

    pub grouped_ciphertext: PodGroupedElGamalCiphertext3Handles, // 128 bytes
}
