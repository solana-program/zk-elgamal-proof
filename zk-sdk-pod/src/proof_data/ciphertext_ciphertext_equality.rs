use {
    crate::{
        encryption::elgamal::{PodElGamalCiphertext, PodElGamalPubkey},
        sigma_proofs::PodCiphertextCiphertextEqualityProof,
    },
    bytemuck_derive::{Pod, Zeroable},
};

/// The instruction data that is needed for the
/// `ProofInstruction::VerifyCiphertextCiphertextEquality` instruction.
///
/// It includes the cryptographic proof as well as the context data information needed to verify
/// the proof.
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct CiphertextCiphertextEqualityProofData {
    pub context: CiphertextCiphertextEqualityProofContext,

    pub proof: PodCiphertextCiphertextEqualityProof,
}

/// The context data needed to verify a ciphertext-ciphertext equality proof.
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct CiphertextCiphertextEqualityProofContext {
    pub first_pubkey: PodElGamalPubkey, // 32 bytes

    pub second_pubkey: PodElGamalPubkey, // 32 bytes

    pub first_ciphertext: PodElGamalCiphertext, // 64 bytes

    pub second_ciphertext: PodElGamalCiphertext, // 64 bytes
}
