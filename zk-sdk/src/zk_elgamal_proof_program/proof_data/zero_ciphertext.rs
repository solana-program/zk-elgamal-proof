//! The zero-ciphertext proof instruction.
//!
//! A zero-ciphertext proof is defined with respect to a twisted ElGamal ciphertext. The proof
//! certifies that a given ciphertext encrypts the message 0 in the field (`Scalar::zero()`). To
//! generate the proof, a prover must provide the decryption key for the ciphertext.

use {
    crate::zk_elgamal_proof_program::proof_data::{ProofContext, ProofType, ZkProofData},
    solana_zk_sdk_pod::{
        encryption::elgamal::{PodElGamalCiphertext, PodElGamalPubkey},
        proof_data::zero_ciphertext::{ZeroCiphertextProofContext, ZeroCiphertextProofData},
    },
};
#[cfg(not(target_os = "solana"))]
use {
    crate::{
        encryption::elgamal::{ElGamalCiphertext, ElGamalKeypair},
        sigma_proofs::zero_ciphertext::ZeroCiphertextProof,
        zk_elgamal_proof_program::errors::{ProofGenerationError, ProofVerificationError},
    },
    bytemuck::bytes_of,
    merlin::Transcript,
    std::convert::TryInto,
};

pub trait ZeroCiphertextProofDataExt {
    fn new(
        keypair: &ElGamalKeypair,
        ciphertext: &ElGamalCiphertext,
    ) -> Result<Self, ProofGenerationError>
    where
        Self: Sized;
}

#[cfg(not(target_os = "solana"))]
impl ZeroCiphertextProofDataExt for ZeroCiphertextProofData {
    fn new(
        keypair: &ElGamalKeypair,
        ciphertext: &ElGamalCiphertext,
    ) -> Result<Self, ProofGenerationError> {
        let pod_pubkey = PodElGamalPubkey(keypair.pubkey().into());
        let pod_ciphertext = PodElGamalCiphertext(ciphertext.to_bytes());

        let context = ZeroCiphertextProofContext {
            pubkey: pod_pubkey,
            ciphertext: pod_ciphertext,
        };

        let mut transcript = context.new_transcript();
        let proof = ZeroCiphertextProof::new(keypair, ciphertext, &mut transcript).into();

        Ok(ZeroCiphertextProofData { context, proof })
    }
}

impl ZkProofData<ZeroCiphertextProofContext> for ZeroCiphertextProofData {
    const PROOF_TYPE: ProofType = ProofType::ZeroCiphertext;

    fn context_data(&self) -> &ZeroCiphertextProofContext {
        &self.context
    }

    #[cfg(not(target_os = "solana"))]
    fn verify_proof(&self) -> Result<(), ProofVerificationError> {
        let mut transcript = self.context.new_transcript();
        let pubkey = self.context.pubkey.try_into()?;
        let ciphertext = self.context.ciphertext.try_into()?;
        let proof: ZeroCiphertextProof = self.proof.try_into()?;
        proof
            .verify(&pubkey, &ciphertext, &mut transcript)
            .map_err(|e| e.into())
    }
}

#[allow(non_snake_case)]
#[cfg(not(target_os = "solana"))]
impl ProofContext for ZeroCiphertextProofContext {
    fn new_transcript(&self) -> Transcript {
        let mut transcript = Transcript::new(b"zero-ciphertext-instruction");

        transcript.append_message(b"pubkey", bytes_of(&self.pubkey));
        transcript.append_message(b"ciphertext", bytes_of(&self.ciphertext));

        transcript
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_zero_ciphertext_proof_instruction_correctness() {
        let keypair = ElGamalKeypair::new_rand();

        // general case: encryption of 0
        let ciphertext = keypair.pubkey().encrypt(0_u64);
        let zero_ciphertext_proof_data =
            ZeroCiphertextProofData::new(&keypair, &ciphertext).unwrap();
        assert!(zero_ciphertext_proof_data.verify_proof().is_ok());

        // general case: encryption of > 0
        let ciphertext = keypair.pubkey().encrypt(1_u64);
        let zero_ciphertext_proof_data =
            ZeroCiphertextProofData::new(&keypair, &ciphertext).unwrap();
        assert!(zero_ciphertext_proof_data.verify_proof().is_err());
    }
}
