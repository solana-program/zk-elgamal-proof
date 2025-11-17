//! The public-key validity proof instruction.
//!
//! A public-key validity proof system is defined with respect to an ElGamal public key. The proof
//! certifies that a given public key is a valid ElGamal public key (i.e. the prover knows a
//! corresponding secret key). To generate the proof, a prover must provide the secret key for the
//! public key.

use {
    crate::zk_elgamal_proof_program::proof_data::{ProofType, ZkProofData},
    solana_zk_sdk_pod::proof_data::pubkey_validity::{
        PubkeyValidityProofContext, PubkeyValidityProofData,
    },
};
#[cfg(not(target_os = "solana"))]
use {
    crate::{
        encryption::elgamal::ElGamalKeypair,
        sigma_proofs::pubkey_validity::PubkeyValidityProof,
        zk_elgamal_proof_program::{
            errors::{ProofGenerationError, ProofVerificationError},
            proof_data::ProofContext,
        },
    },
    bytemuck::bytes_of,
    merlin::Transcript,
    solana_zk_sdk_pod::encryption::elgamal::PodElGamalPubkey,
    std::convert::TryInto,
};

#[cfg(not(target_os = "solana"))]
pub trait PubkeyValidityProofDataExt {
    fn new(keypair: &ElGamalKeypair) -> Result<Self, ProofGenerationError>
    where
        Self: Sized;
}

#[cfg(not(target_os = "solana"))]
impl PubkeyValidityProofDataExt for PubkeyValidityProofData {
    fn new(keypair: &ElGamalKeypair) -> Result<Self, ProofGenerationError> {
        let pod_pubkey = PodElGamalPubkey(keypair.pubkey().into());

        let context = PubkeyValidityProofContext { pubkey: pod_pubkey };

        let mut transcript = context.new_transcript();
        let proof = PubkeyValidityProof::new(keypair, &mut transcript).into();

        Ok(PubkeyValidityProofData { context, proof })
    }
}

impl ZkProofData<PubkeyValidityProofContext> for PubkeyValidityProofData {
    const PROOF_TYPE: ProofType = ProofType::PubkeyValidity;

    fn context_data(&self) -> &PubkeyValidityProofContext {
        &self.context
    }

    #[cfg(not(target_os = "solana"))]
    fn verify_proof(&self) -> Result<(), ProofVerificationError> {
        let mut transcript = self.context.new_transcript();
        let pubkey = self.context.pubkey.try_into()?;
        let proof: PubkeyValidityProof = self.proof.try_into()?;
        proof.verify(&pubkey, &mut transcript).map_err(|e| e.into())
    }
}

#[allow(non_snake_case)]
#[cfg(not(target_os = "solana"))]
impl ProofContext for PubkeyValidityProofContext {
    fn new_transcript(&self) -> Transcript {
        let mut transcript = Transcript::new(b"pubkey-validity-instruction");
        transcript.append_message(b"pubkey", bytes_of(&self.pubkey));
        transcript
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_pubkey_validity_instruction_correctness() {
        let keypair = ElGamalKeypair::new_rand();

        let pubkey_validity_data = PubkeyValidityProofData::new(&keypair).unwrap();
        assert!(pubkey_validity_data.verify_proof().is_ok());
    }
}
