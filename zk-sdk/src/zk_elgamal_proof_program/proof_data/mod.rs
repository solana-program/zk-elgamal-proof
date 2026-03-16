use crate::zk_elgamal_proof_program::errors::ProofVerificationError;

pub mod batched_grouped_ciphertext_validity;
pub mod batched_range_proof;
pub mod ciphertext_ciphertext_equality;
pub mod ciphertext_commitment_equality;
// pub mod errors;
pub mod grouped_ciphertext_validity;
pub mod percentage_with_cap;
// pub mod pod;
pub mod pubkey_validity;
pub mod zero_ciphertext;

pub use {
    batched_grouped_ciphertext_validity::*, batched_range_proof::*,
    ciphertext_ciphertext_equality::*, ciphertext_commitment_equality::*,
    grouped_ciphertext_validity::*, percentage_with_cap::*, pubkey_validity::*, zero_ciphertext::*,
};

pub trait VerifyZkProof {
    fn verify_proof(&self) -> Result<(), ProofVerificationError>;
}
