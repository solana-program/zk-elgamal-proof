use {
    crate::{
        encryption::{
            elgamal::{ElGamalCiphertext, ElGamalKeypair},
            pedersen::{Pedersen, PedersenCommitment, PedersenOpening, G},
        },
        sigma_proofs::ciphertext_commitment_equality::CiphertextCommitmentEqualityProof,
        transcript::TranscriptProtocol,
        zk_elgamal_proof_program::{
            errors::{ProofGenerationError, ProofVerificationError},
            VerifyZkProof,
        },
    },
    curve25519_dalek::scalar::Scalar,
    merlin::Transcript,
    solana_zk_elgamal_proof_program::proof_data::{
        CiphertextCommitmentEqualityProofContext, CiphertextCommitmentEqualityProofData,
    },
    solana_zk_sdk_pod::encryption::{
        elgamal::{PodElGamalCiphertext, PodElGamalPubkey},
        pedersen::PodPedersenCommitment,
    },
    std::convert::TryInto,
};

pub fn build_ciphertext_commitment_equality_proof_data(
    keypair: &ElGamalKeypair,
    ciphertext: &ElGamalCiphertext,
    commitment: &PedersenCommitment,
    opening: &PedersenOpening,
    amount: u64,
) -> Result<CiphertextCommitmentEqualityProofData, ProofGenerationError> {
    // Ciphertext should decrypt to amount
    let decrypted_point = ciphertext.decrypt(keypair.secret()).target;
    let expected_point = Scalar::from(amount) * G;
    if decrypted_point != expected_point {
        return Err(ProofGenerationError::InconsistentInput);
    }

    // Commitment should match amount and opening
    let expected_commitment = Pedersen::with(amount, opening);
    if *commitment != expected_commitment {
        return Err(ProofGenerationError::InconsistentInput);
    }

    let context = CiphertextCommitmentEqualityProofContext {
        pubkey: PodElGamalPubkey(keypair.pubkey().into()),
        ciphertext: PodElGamalCiphertext(ciphertext.to_bytes()),
        commitment: PodPedersenCommitment(commitment.to_bytes()),
    };
    let mut transcript =
        Transcript::new_zk_elgamal_transcript(b"ciphertext-commitment-equality-instruction");
    let proof = CiphertextCommitmentEqualityProof::new(
        keypair,
        ciphertext,
        commitment,
        opening,
        amount,
        &mut transcript,
    );
    Ok(CiphertextCommitmentEqualityProofData {
        context,
        proof: proof.into(),
    })
}

impl VerifyZkProof for CiphertextCommitmentEqualityProofData {
    fn verify_proof(&self) -> Result<(), ProofVerificationError> {
        let mut transcript =
            Transcript::new_zk_elgamal_transcript(b"ciphertext-commitment-equality-instruction");

        let pubkey = self.context.pubkey.try_into()?;
        let ciphertext = self.context.ciphertext.try_into()?;
        let commitment = self.context.commitment.try_into()?;
        let proof: CiphertextCommitmentEqualityProof = self.proof.try_into()?;

        proof
            .verify(&pubkey, &ciphertext, &commitment, &mut transcript)
            .map_err(|e| e.into())
    }
}

#[cfg(test)]
mod test {
    use {
        super::*,
        crate::encryption::{elgamal::ElGamalKeypair, pedersen::Pedersen},
    };

    #[test]
    fn test_ctxt_comm_equality_proof_correctness() {
        let keypair = ElGamalKeypair::new_rand();
        let amount: u64 = 55;
        let ciphertext = keypair.pubkey().encrypt(amount);
        let (commitment, opening) = Pedersen::new(amount);

        let proof_data = build_ciphertext_commitment_equality_proof_data(
            &keypair,
            &ciphertext,
            &commitment,
            &opening,
            amount,
        )
        .unwrap();

        assert!(proof_data.verify_proof().is_ok());

        let amount_2 = 77_u64;
        let (commitment_2, opening_2) = Pedersen::new(amount_2);

        let result = build_ciphertext_commitment_equality_proof_data(
            &keypair,
            &ciphertext,
            &commitment_2,
            &opening_2,
            amount,
        );

        assert_eq!(result, Err(ProofGenerationError::InconsistentInput));
    }
}
