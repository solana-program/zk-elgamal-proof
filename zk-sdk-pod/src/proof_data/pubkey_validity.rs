use {
    crate::{encryption::elgamal::PodElGamalPubkey, sigma_proofs::PodPubkeyValidityProof},
    bytemuck_derive::{Pod, Zeroable},
};

/// The instruction data that is needed for the `ProofInstruction::VerifyPubkeyValidity`
/// instruction.
///
/// It includes the cryptographic proof as well as the context data information needed to verify
/// the proof.
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct PubkeyValidityProofData {
    /// The context data for the public key validity proof
    pub context: PubkeyValidityProofContext, // 32 bytes

    /// Proof that the public key is well-formed
    pub proof: PodPubkeyValidityProof, // 64 bytes
}

/// The context data needed to verify a pubkey validity proof.
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct PubkeyValidityProofContext {
    /// The public key to be proved
    pub pubkey: PodElGamalPubkey, // 32 bytes
}
