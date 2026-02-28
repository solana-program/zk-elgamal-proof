//! The grouped-ciphertext with 3 decryption handles validity proof instruction.
//!
//! A grouped-ciphertext validity proof certifies that a grouped ElGamal ciphertext is
//! well-defined, i.e. the ciphertext can be decrypted by private keys associated with its
//! decryption handles. To generate the proof, a prover must provide the Pedersen opening
//! associated with the grouped ciphertext's commitment.

use {
    crate::{
        encryption::pod::{
            elgamal::PodElGamalPubkey, grouped_elgamal::PodGroupedElGamalCiphertext3Handles,
        },
        sigma_proofs::pod::PodGroupedCiphertext3HandlesValidityProof,
        zk_elgamal_proof_program::proof_data::{ProofType, ZkProofData},
    },
    bytemuck_derive::{Pod, Zeroable},
};
#[cfg(not(target_os = "solana"))]
use {
    crate::{
        encryption::{
            elgamal::ElGamalPubkey,
            grouped_elgamal::{GroupedElGamal, GroupedElGamalCiphertext},
            pedersen::PedersenOpening,
        },
        sigma_proofs::grouped_ciphertext_validity::GroupedCiphertext3HandlesValidityProof,
        transcript::TranscriptProtocol,
        zk_elgamal_proof_program::{
            errors::{ProofGenerationError, ProofVerificationError},
            proof_data::VerifyZkProof,
        },
    },
    merlin::Transcript,
};

/// The instruction data that is needed for the
/// `ProofInstruction::VerifyGroupedCiphertext3HandlesValidity` instruction.
///
/// It includes the cryptographic proof as well as the context data information needed to verify
/// the proof.
#[derive(Clone, Copy, Pod, Zeroable, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct GroupedCiphertext3HandlesValidityProofData {
    pub context: GroupedCiphertext3HandlesValidityProofContext,

    pub proof: PodGroupedCiphertext3HandlesValidityProof,
}

#[derive(Clone, Copy, Pod, Zeroable, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct GroupedCiphertext3HandlesValidityProofContext {
    pub first_pubkey: PodElGamalPubkey, // 32 bytes

    pub second_pubkey: PodElGamalPubkey, // 32 bytes

    pub third_pubkey: PodElGamalPubkey, // 32 bytes

    pub grouped_ciphertext: PodGroupedElGamalCiphertext3Handles, // 128 bytes
}

#[cfg(not(target_os = "solana"))]
pub fn build_grouped_ciphertext_3_handles_validity_proof_data(
    first_pubkey: &ElGamalPubkey,
    second_pubkey: &ElGamalPubkey,
    third_pubkey: &ElGamalPubkey,
    grouped_ciphertext: &GroupedElGamalCiphertext<3>,
    amount: u64,
    opening: &PedersenOpening,
) -> Result<GroupedCiphertext3HandlesValidityProofData, ProofGenerationError> {
    let expected_ciphertext =
        GroupedElGamal::encrypt_with([first_pubkey, second_pubkey, third_pubkey], amount, opening);
    if *grouped_ciphertext != expected_ciphertext {
        return Err(ProofGenerationError::InconsistentInput);
    }

    let pod_first_pubkey = PodElGamalPubkey(first_pubkey.into());
    let pod_second_pubkey = PodElGamalPubkey(second_pubkey.into());
    let pod_third_pubkey = PodElGamalPubkey(third_pubkey.into());
    let pod_grouped_ciphertext = (*grouped_ciphertext).into();

    let context = GroupedCiphertext3HandlesValidityProofContext {
        first_pubkey: pod_first_pubkey,
        second_pubkey: pod_second_pubkey,
        third_pubkey: pod_third_pubkey,
        grouped_ciphertext: pod_grouped_ciphertext,
    };

    let mut transcript =
        Transcript::new_zk_elgamal_transcript(b"grouped-ciphertext-validity-3-handles-instruction");

    let proof = GroupedCiphertext3HandlesValidityProof::new(
        first_pubkey,
        second_pubkey,
        third_pubkey,
        grouped_ciphertext,
        amount,
        opening,
        &mut transcript,
    )
    .into();

    Ok(GroupedCiphertext3HandlesValidityProofData { context, proof })
}

impl ZkProofData<GroupedCiphertext3HandlesValidityProofContext>
    for GroupedCiphertext3HandlesValidityProofData
{
    const PROOF_TYPE: ProofType = ProofType::GroupedCiphertext3HandlesValidity;

    fn context_data(&self) -> &GroupedCiphertext3HandlesValidityProofContext {
        &self.context
    }
}

#[cfg(not(target_os = "solana"))]
impl VerifyZkProof for GroupedCiphertext3HandlesValidityProofData {
    fn verify_proof(&self) -> Result<(), ProofVerificationError> {
        let mut transcript = Transcript::new_zk_elgamal_transcript(
            b"grouped-ciphertext-validity-3-handles-instruction",
        );

        let first_pubkey = self.context.first_pubkey.try_into()?;
        let second_pubkey = self.context.second_pubkey.try_into()?;
        let third_pubkey = self.context.third_pubkey.try_into()?;
        let grouped_ciphertext: GroupedElGamalCiphertext<3> =
            self.context.grouped_ciphertext.try_into()?;

        let proof: GroupedCiphertext3HandlesValidityProof = self.proof.try_into()?;

        proof
            .verify(
                &first_pubkey,
                &second_pubkey,
                &third_pubkey,
                &grouped_ciphertext,
                &mut transcript,
            )
            .map_err(|e| e.into())
    }
}

#[cfg(test)]
mod test {
    use {
        super::*,
        crate::encryption::{
            elgamal::ElGamalKeypair, grouped_elgamal::GroupedElGamal, pedersen::PedersenOpening,
        },
    };

    #[test]
    fn test_ciphertext_validity_proof_instruction_correctness() {
        let first_keypair = ElGamalKeypair::new_rand();
        let first_pubkey = first_keypair.pubkey();

        let second_keypair = ElGamalKeypair::new_rand();
        let second_pubkey = second_keypair.pubkey();

        let third_keypair = ElGamalKeypair::new_rand();
        let third_pubkey = third_keypair.pubkey();

        let amount: u64 = 55;
        let opening = PedersenOpening::new_rand();
        let grouped_ciphertext = GroupedElGamal::encrypt_with(
            [first_pubkey, second_pubkey, third_pubkey],
            amount,
            &opening,
        );

        let proof_data = build_grouped_ciphertext_3_handles_validity_proof_data(
            first_pubkey,
            second_pubkey,
            third_pubkey,
            &grouped_ciphertext,
            amount,
            &opening,
        )
        .unwrap();

        assert!(proof_data.verify_proof().is_ok());

        let wrong_opening = PedersenOpening::new_rand();
        let result = build_grouped_ciphertext_3_handles_validity_proof_data(
            first_keypair.pubkey(),
            second_keypair.pubkey(),
            third_keypair.pubkey(),
            &grouped_ciphertext,
            amount,
            &wrong_opening,
        );
        assert_eq!(result, Err(ProofGenerationError::InconsistentInput));
    }
}
