use {
    crate::{
        encryption::{
            elgamal::{PodElGamalCiphertext, PodElGamalPubkey},
            pedersen::PodPedersenCommitment,
        },
        sigma_proofs::PodCiphertextCommitmentEqualityProof,
    },
    bytemuck_derive::{Pod, Zeroable},
};

/// The instruction data that is needed for the
/// `ProofInstruction::VerifyCiphertextCommitmentEquality` instruction.
///
/// It includes the cryptographic proof as well as the context data information needed to verify
/// the proof.
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct CiphertextCommitmentEqualityProofData {
    pub context: CiphertextCommitmentEqualityProofContext,
    pub proof: PodCiphertextCommitmentEqualityProof,
}

/// The context data needed to verify a ciphertext-commitment equality proof.
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct CiphertextCommitmentEqualityProofContext {
    /// The ElGamal pubkey
    pub pubkey: PodElGamalPubkey, // 32 bytes

    /// The ciphertext encrypted under the ElGamal pubkey
    pub ciphertext: PodElGamalCiphertext, // 64 bytes

    /// The Pedersen commitment
    pub commitment: PodPedersenCommitment, // 32 bytes
}
