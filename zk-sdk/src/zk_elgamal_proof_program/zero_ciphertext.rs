use {
    crate::{
        encryption::elgamal::{ElGamalCiphertext, ElGamalKeypair},
        sigma_proofs::zero_ciphertext::ZeroCiphertextProof,
        transcript::TranscriptProtocol,
        zk_elgamal_proof_program::{
            errors::{ProofGenerationError, ProofVerificationError},
            VerifyZkProof,
        },
    },
    curve25519_dalek::traits::IsIdentity,
    merlin::Transcript,
    solana_zk_elgamal_proof_program::proof_data::{
        ZeroCiphertextProofContext, ZeroCiphertextProofData,
    },
    solana_zk_sdk_pod::encryption::elgamal::{PodElGamalCiphertext, PodElGamalPubkey},
    std::convert::TryInto,
};

pub fn build_zero_ciphertext_proof_data(
    keypair: &ElGamalKeypair,
    ciphertext: &ElGamalCiphertext,
) -> Result<ZeroCiphertextProofData, ProofGenerationError> {
    // Ciphertext should decrypt to Identity
    let decrypted_point = ciphertext.decrypt(keypair.secret()).target;
    if !decrypted_point.is_identity() {
        return Err(ProofGenerationError::InconsistentInput);
    }

    let pod_pubkey = PodElGamalPubkey(keypair.pubkey().into());
    let pod_ciphertext = PodElGamalCiphertext(ciphertext.to_bytes());

    let context = ZeroCiphertextProofContext {
        pubkey: pod_pubkey,
        ciphertext: pod_ciphertext,
    };

    let mut transcript = Transcript::new_zk_elgamal_transcript(b"zero-ciphertext-instruction");
    let proof = ZeroCiphertextProof::new(keypair, ciphertext, &mut transcript).into();

    Ok(ZeroCiphertextProofData { context, proof })
}

impl VerifyZkProof for ZeroCiphertextProofData {
    fn verify_proof(&self) -> Result<(), ProofVerificationError> {
        let mut transcript = Transcript::new_zk_elgamal_transcript(b"zero-ciphertext-instruction");
        let pubkey = self.context.pubkey.try_into()?;
        let ciphertext = self.context.ciphertext.try_into()?;
        let proof: ZeroCiphertextProof = self.proof.try_into()?;
        proof
            .verify(&pubkey, &ciphertext, &mut transcript)
            .map_err(|e| e.into())
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
            build_zero_ciphertext_proof_data(&keypair, &ciphertext).unwrap();
        assert!(zero_ciphertext_proof_data.verify_proof().is_ok());

        // general case: encryption of > 0
        let ciphertext = keypair.pubkey().encrypt(1_u64);
        let result = build_zero_ciphertext_proof_data(&keypair, &ciphertext);
        assert_eq!(result, Err(ProofGenerationError::InconsistentInput));
    }
}
