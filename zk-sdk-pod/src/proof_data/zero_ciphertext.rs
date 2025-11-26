use {
    crate::{
        encryption::elgamal::{PodElGamalCiphertext, PodElGamalPubkey},
        sigma_proofs::PodZeroCiphertextProof,
    },
    bytemuck_derive::{Pod, Zeroable},
};

/// The instruction data that is needed for the `ProofInstruction::VerifyZeroCiphertext` instruction.
///
/// It includes the cryptographic proof as well as the context data information needed to verify
/// the proof.
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct ZeroCiphertextProofData {
    /// The context data for the zero-ciphertext proof
    pub context: ZeroCiphertextProofContext, // 96 bytes

    /// Proof that the ciphertext is zero
    pub proof: PodZeroCiphertextProof, // 96 bytes
}

/// The context data needed to verify a zero-ciphertext proof.
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct ZeroCiphertextProofContext {
    /// The ElGamal pubkey associated with the ElGamal ciphertext
    pub pubkey: PodElGamalPubkey, // 32 bytes

    /// The ElGamal ciphertext that encrypts zero
    pub ciphertext: PodElGamalCiphertext, // 64 bytes
}
