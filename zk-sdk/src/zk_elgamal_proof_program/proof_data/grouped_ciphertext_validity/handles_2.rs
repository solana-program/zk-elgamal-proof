//! The grouped-ciphertext validity proof instruction.
//!
//! A grouped-ciphertext validity proof certifies that a grouped ElGamal ciphertext is
//! well-defined, i.e. the ciphertext can be decrypted by private keys associated with its
//! decryption handles. To generate the proof, a prover must provide the Pedersen opening
//! associated with the grouped ciphertext's commitment.

use {
    crate::{
        encryption::pod::{
            elgamal::PodElGamalPubkey, grouped_elgamal::PodGroupedElGamalCiphertext2Handles,
        },
        sigma_proofs::pod::PodGroupedCiphertext2HandlesValidityProof,
        zk_elgamal_proof_program::proof_data::{ProofType, ZkProofData},
    },
    bytemuck_derive::{Pod, Zeroable},
};
#[cfg(not(target_os = "solana"))]
use {
    crate::{
        encryption::{
            elgamal::ElGamalPubkey, grouped_elgamal::GroupedElGamalCiphertext,
            pedersen::PedersenOpening,
        },
        sigma_proofs::grouped_ciphertext_validity::GroupedCiphertext2HandlesValidityProof,
        transcript::TranscriptProtocol,
        zk_elgamal_proof_program::errors::{ProofGenerationError, ProofVerificationError},
    },
    merlin::Transcript,
};

/// The instruction data that is needed for the `ProofInstruction::VerifyGroupedCiphertextValidity`
/// instruction.
///
/// It includes the cryptographic proof as well as the context data information needed to verify
/// the proof.
#[derive(Clone, Copy, Pod, Zeroable, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct GroupedCiphertext2HandlesValidityProofData {
    pub context: GroupedCiphertext2HandlesValidityProofContext,

    pub proof: PodGroupedCiphertext2HandlesValidityProof,
}

#[derive(Clone, Copy, Pod, Zeroable, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct GroupedCiphertext2HandlesValidityProofContext {
    pub first_pubkey: PodElGamalPubkey, // 32 bytes

    pub second_pubkey: PodElGamalPubkey, // 32 bytes

    pub grouped_ciphertext: PodGroupedElGamalCiphertext2Handles, // 96 bytes
}

#[cfg(not(target_os = "solana"))]
impl GroupedCiphertext2HandlesValidityProofData {
    pub fn new(
        first_pubkey: &ElGamalPubkey,
        second_pubkey: &ElGamalPubkey,
        grouped_ciphertext: &GroupedElGamalCiphertext<2>,
        amount: u64,
        opening: &PedersenOpening,
    ) -> Result<Self, ProofGenerationError> {
        let pod_first_pubkey = PodElGamalPubkey(first_pubkey.into());
        let pod_second_pubkey = PodElGamalPubkey(second_pubkey.into());
        let pod_grouped_ciphertext = (*grouped_ciphertext).into();

        let context = GroupedCiphertext2HandlesValidityProofContext {
            first_pubkey: pod_first_pubkey,
            second_pubkey: pod_second_pubkey,
            grouped_ciphertext: pod_grouped_ciphertext,
        };

        let mut transcript = Transcript::new_zk_elgamal_transcript(
            b"grouped-ciphertext-validity-2-handles-instruction",
        );

        let proof = GroupedCiphertext2HandlesValidityProof::new(
            first_pubkey,
            second_pubkey,
            grouped_ciphertext,
            amount,
            opening,
            &mut transcript,
        )
        .into();

        Ok(Self { context, proof })
    }
}

impl ZkProofData<GroupedCiphertext2HandlesValidityProofContext>
    for GroupedCiphertext2HandlesValidityProofData
{
    const PROOF_TYPE: ProofType = ProofType::GroupedCiphertext2HandlesValidity;

    fn context_data(&self) -> &GroupedCiphertext2HandlesValidityProofContext {
        &self.context
    }

    #[cfg(not(target_os = "solana"))]
    fn verify_proof(&self) -> Result<(), ProofVerificationError> {
        let mut transcript = Transcript::new_zk_elgamal_transcript(
            b"grouped-ciphertext-validity-2-handles-instruction",
        );

        let first_pubkey = self.context.first_pubkey.try_into()?;
        let second_pubkey = self.context.second_pubkey.try_into()?;
        let grouped_ciphertext: GroupedElGamalCiphertext<2> =
            self.context.grouped_ciphertext.try_into()?;

        let proof: GroupedCiphertext2HandlesValidityProof = self.proof.try_into()?;

        proof
            .verify(
                &first_pubkey,
                &second_pubkey,
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
        crate::{
            encryption::{elgamal::ElGamalKeypair, grouped_elgamal::GroupedElGamal},
            zk_elgamal_proof_program::proof_data::ZkProofData,
        },
    };

    #[test]
    fn test_ciphertext_validity_proof_instruction_correctness() {
        let first_keypair = ElGamalKeypair::new_rand();
        let first_pubkey = first_keypair.pubkey();

        let second_keypair = ElGamalKeypair::new_rand();
        let second_pubkey = second_keypair.pubkey();

        let amount: u64 = 55;
        let opening = PedersenOpening::new_rand();
        let grouped_ciphertext =
            GroupedElGamal::encrypt_with([first_pubkey, second_pubkey], amount, &opening);

        let proof_data = GroupedCiphertext2HandlesValidityProofData::new(
            first_pubkey,
            second_pubkey,
            &grouped_ciphertext,
            amount,
            &opening,
        )
        .unwrap();

        assert!(proof_data.verify_proof().is_ok());
    }
}
