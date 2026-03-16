#[cfg(not(target_os = "solana"))]
use {
    crate::{
        encryption::elgamal::ElGamalKeypair,
        sigma_proofs::pubkey_validity::PubkeyValidityProof,
        transcript::TranscriptProtocol,
        zk_elgamal_proof_program::{
            errors::{ProofGenerationError, ProofVerificationError},
            proof_data::VerifyZkProof,
        },
    },
    merlin::Transcript,
    solana_zk_elgamal_proof_program::proof_data::{
        PubkeyValidityProofContext, PubkeyValidityProofData,
    },
    solana_zk_sdk_pod::encryption::elgamal::PodElGamalPubkey,
    std::convert::TryInto,
};

#[cfg(not(target_os = "solana"))]
pub fn build_pubkey_validity_proof_data(
    keypair: &ElGamalKeypair,
) -> Result<PubkeyValidityProofData, ProofGenerationError> {
    let pod_pubkey = PodElGamalPubkey(keypair.pubkey().into());

    let context = PubkeyValidityProofContext { pubkey: pod_pubkey };

    let mut transcript = Transcript::new_zk_elgamal_transcript(b"pubkey-validity-instruction");
    let proof = PubkeyValidityProof::new(keypair, &mut transcript).into();

    Ok(PubkeyValidityProofData { context, proof })
}

#[cfg(not(target_os = "solana"))]
impl VerifyZkProof for PubkeyValidityProofData {
    fn verify_proof(&self) -> Result<(), ProofVerificationError> {
        let mut transcript = Transcript::new_zk_elgamal_transcript(b"pubkey-validity-instruction");
        let pubkey = self.context.pubkey.try_into()?;
        let proof: PubkeyValidityProof = self.proof.try_into()?;
        proof.verify(&pubkey, &mut transcript).map_err(|e| e.into())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_pubkey_validity_instruction_correctness() {
        let keypair = ElGamalKeypair::new_rand();

        let pubkey_validity_data = build_pubkey_validity_proof_data(&keypair).unwrap();
        assert!(pubkey_validity_data.verify_proof().is_ok());
    }
}
