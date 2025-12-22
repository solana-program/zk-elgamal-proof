use {
    crate::{
        encryption::{
            elgamal::PodElGamalPubkey, grouped_elgamal::PodGroupedElGamalCiphertext2Handles,
        },
        sigma_proofs::PodGroupedCiphertext2HandlesValidityProof,
    },
    bytemuck_derive::{Pod, Zeroable},
};

/// The instruction data that is needed for the `ProofInstruction::VerifyGroupedCiphertextValidity`
/// instruction.
///
/// It includes the cryptographic proof as well as the context data information needed to verify
/// the proof.
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct GroupedCiphertext2HandlesValidityProofData {
    pub context: GroupedCiphertext2HandlesValidityProofContext,

    pub proof: PodGroupedCiphertext2HandlesValidityProof,
}

#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct GroupedCiphertext2HandlesValidityProofContext {
    pub first_pubkey: PodElGamalPubkey, // 32 bytes

    pub second_pubkey: PodElGamalPubkey, // 32 bytes

    pub grouped_ciphertext: PodGroupedElGamalCiphertext2Handles, // 96 bytes
}
