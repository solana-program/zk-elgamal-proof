use {
    crate::{
        encryption::{
            elgamal::ElGamalPubkey,
            grouped_elgamal::{GroupedElGamal, GroupedElGamalCiphertext},
            pedersen::PedersenOpening,
        },
        sigma_proofs::batched_grouped_ciphertext_validity::BatchedGroupedCiphertext2HandlesValidityProof,
        transcript::TranscriptProtocol,
        zk_elgamal_proof_program::{
            errors::{ProofGenerationError, ProofVerificationError},
            VerifyZkProof,
        },
    },
    merlin::Transcript,
    solana_zk_elgamal_proof_interface::proof_data::{
        BatchedGroupedCiphertext2HandlesValidityProofContext,
        BatchedGroupedCiphertext2HandlesValidityProofData,
    },
    solana_zk_sdk_pod::encryption::elgamal::PodElGamalPubkey,
};

#[allow(clippy::too_many_arguments)]
pub fn build_batched_grouped_ciphertext_2_handles_validity_proof_data(
    first_pubkey: &ElGamalPubkey,
    second_pubkey: &ElGamalPubkey,
    grouped_ciphertext_lo: &GroupedElGamalCiphertext<2>,
    grouped_ciphertext_hi: &GroupedElGamalCiphertext<2>,
    amount_lo: u64,
    amount_hi: u64,
    opening_lo: &PedersenOpening,
    opening_hi: &PedersenOpening,
) -> Result<BatchedGroupedCiphertext2HandlesValidityProofData, ProofGenerationError> {
    let expected_lo =
        GroupedElGamal::encrypt_with([first_pubkey, second_pubkey], amount_lo, opening_lo);
    if *grouped_ciphertext_lo != expected_lo {
        return Err(ProofGenerationError::InconsistentInput);
    }

    let expected_hi =
        GroupedElGamal::encrypt_with([first_pubkey, second_pubkey], amount_hi, opening_hi);
    if *grouped_ciphertext_hi != expected_hi {
        return Err(ProofGenerationError::InconsistentInput);
    }

    let pod_first_pubkey = PodElGamalPubkey(first_pubkey.into());
    let pod_second_pubkey = PodElGamalPubkey(second_pubkey.into());
    let pod_grouped_ciphertext_lo = (*grouped_ciphertext_lo).into();
    let pod_grouped_ciphertext_hi = (*grouped_ciphertext_hi).into();

    let context = BatchedGroupedCiphertext2HandlesValidityProofContext {
        first_pubkey: pod_first_pubkey,
        second_pubkey: pod_second_pubkey,
        grouped_ciphertext_lo: pod_grouped_ciphertext_lo,
        grouped_ciphertext_hi: pod_grouped_ciphertext_hi,
    };

    let mut transcript = Transcript::new_zk_elgamal_transcript(
        b"batched-grouped-ciphertext-validity-2-handles-instruction",
    );

    let proof = BatchedGroupedCiphertext2HandlesValidityProof::new(
        first_pubkey,
        second_pubkey,
        grouped_ciphertext_lo,
        grouped_ciphertext_hi,
        amount_lo,
        amount_hi,
        opening_lo,
        opening_hi,
        &mut transcript,
    )
    .into();

    Ok(BatchedGroupedCiphertext2HandlesValidityProofData { context, proof })
}

impl VerifyZkProof for BatchedGroupedCiphertext2HandlesValidityProofData {
    fn verify_proof(&self) -> Result<(), ProofVerificationError> {
        let mut transcript = Transcript::new_zk_elgamal_transcript(
            b"batched-grouped-ciphertext-validity-2-handles-instruction",
        );

        let first_pubkey = self.context.first_pubkey.try_into()?;
        let second_pubkey = self.context.second_pubkey.try_into()?;
        let grouped_ciphertext_lo: GroupedElGamalCiphertext<2> =
            self.context.grouped_ciphertext_lo.try_into()?;
        let grouped_ciphertext_hi: GroupedElGamalCiphertext<2> =
            self.context.grouped_ciphertext_hi.try_into()?;

        let proof: BatchedGroupedCiphertext2HandlesValidityProof = self.proof.try_into()?;

        proof
            .verify(
                &first_pubkey,
                &second_pubkey,
                &grouped_ciphertext_lo,
                &grouped_ciphertext_hi,
                &mut transcript,
            )
            .map_err(|e| e.into())
    }
}

#[cfg(test)]
mod test {
    use {
        super::*,
        crate::encryption::{elgamal::ElGamalKeypair, grouped_elgamal::GroupedElGamal},
    };

    #[test]
    fn test_ciphertext_validity_proof_instruction_correctness() {
        let first_keypair = ElGamalKeypair::new_rand();
        let first_pubkey = first_keypair.pubkey();

        let second_keypair = ElGamalKeypair::new_rand();
        let second_pubkey = second_keypair.pubkey();

        let amount_lo: u64 = 11;
        let amount_hi: u64 = 22;

        let opening_lo = PedersenOpening::new_rand();
        let opening_hi = PedersenOpening::new_rand();

        let grouped_ciphertext_lo =
            GroupedElGamal::encrypt_with([first_pubkey, second_pubkey], amount_lo, &opening_lo);

        let grouped_ciphertext_hi =
            GroupedElGamal::encrypt_with([first_pubkey, second_pubkey], amount_hi, &opening_hi);

        let proof_data = build_batched_grouped_ciphertext_2_handles_validity_proof_data(
            first_pubkey,
            second_pubkey,
            &grouped_ciphertext_lo,
            &grouped_ciphertext_hi,
            amount_lo,
            amount_hi,
            &opening_lo,
            &opening_hi,
        )
        .unwrap();

        assert!(proof_data.verify_proof().is_ok());

        let result = build_batched_grouped_ciphertext_2_handles_validity_proof_data(
            first_keypair.pubkey(),
            second_keypair.pubkey(),
            &grouped_ciphertext_hi, // Swapped: Passed Hi ciphertext
            &grouped_ciphertext_lo, // Swapped: Passed Lo ciphertext
            amount_lo,              // Claiming Lo amount
            amount_hi,              // Claiming Hi amount
            &opening_lo,            // Claiming Lo opening
            &opening_hi,            // Claiming Hi opening
        );
        assert_eq!(result, Err(ProofGenerationError::InconsistentInput));
    }
}
