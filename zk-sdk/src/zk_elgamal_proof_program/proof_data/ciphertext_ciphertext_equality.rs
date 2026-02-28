//! The ciphertext-ciphertext equality proof instruction.
//!
//! A ciphertext-ciphertext equality proof is defined with respect to two twisted ElGamal
//! ciphertexts. The proof certifies that the two ciphertexts encrypt the same message. To generate
//! the proof, a prover must provide the decryption key for the first ciphertext and the randomness
//! used to generate the second ciphertext.

use {
    crate::{
        encryption::pod::elgamal::{PodElGamalCiphertext, PodElGamalPubkey},
        sigma_proofs::pod::PodCiphertextCiphertextEqualityProof,
        zk_elgamal_proof_program::proof_data::{ProofType, ZkProofData},
    },
    bytemuck_derive::{Pod, Zeroable},
};
#[cfg(not(target_os = "solana"))]
use {
    crate::{
        encryption::{
            elgamal::{ElGamalCiphertext, ElGamalKeypair, ElGamalPubkey},
            pedersen::{PedersenOpening, G},
        },
        sigma_proofs::ciphertext_ciphertext_equality::CiphertextCiphertextEqualityProof,
        transcript::TranscriptProtocol,
        zk_elgamal_proof_program::{
            errors::{ProofGenerationError, ProofVerificationError},
            proof_data::VerifyZkProof,
        },
    },
    curve25519_dalek::scalar::Scalar,
    merlin::Transcript,
    std::convert::TryInto,
};

/// The instruction data that is needed for the
/// `ProofInstruction::VerifyCiphertextCiphertextEquality` instruction.
///
/// It includes the cryptographic proof as well as the context data information needed to verify
/// the proof.
#[derive(Clone, Copy, Pod, Zeroable, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct CiphertextCiphertextEqualityProofData {
    pub context: CiphertextCiphertextEqualityProofContext,

    pub proof: PodCiphertextCiphertextEqualityProof,
}

/// The context data needed to verify a ciphertext-ciphertext equality proof.
#[derive(Clone, Copy, Pod, Zeroable, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct CiphertextCiphertextEqualityProofContext {
    pub first_pubkey: PodElGamalPubkey, // 32 bytes

    pub second_pubkey: PodElGamalPubkey, // 32 bytes

    pub first_ciphertext: PodElGamalCiphertext, // 64 bytes

    pub second_ciphertext: PodElGamalCiphertext, // 64 bytes
}

#[cfg(not(target_os = "solana"))]
pub fn build_ciphertext_ciphertext_equality_proof_data(
    first_keypair: &ElGamalKeypair,
    second_pubkey: &ElGamalPubkey,
    first_ciphertext: &ElGamalCiphertext,
    second_ciphertext: &ElGamalCiphertext,
    second_opening: &PedersenOpening,
    amount: u64,
) -> Result<CiphertextCiphertextEqualityProofData, ProofGenerationError> {
    // First ciphertext should decrypt to the expected amount
    // D_first = C_first - s * H_first. Should equal amount * G.
    let decrypted_point = first_ciphertext.decrypt(first_keypair.secret()).target;
    let expected_point = Scalar::from(amount) * G;
    if decrypted_point != expected_point {
        return Err(ProofGenerationError::InconsistentInput);
    }

    // Second ciphertext should match encryption of amount with second_opening
    let expected_second_ciphertext = second_pubkey.encrypt_with(amount, second_opening);
    if *second_ciphertext != expected_second_ciphertext {
        return Err(ProofGenerationError::InconsistentInput);
    }

    let pod_first_pubkey = PodElGamalPubkey(first_keypair.pubkey().into());
    let pod_second_pubkey = PodElGamalPubkey(second_pubkey.into());
    let pod_first_ciphertext = PodElGamalCiphertext(first_ciphertext.to_bytes());
    let pod_second_ciphertext = PodElGamalCiphertext(second_ciphertext.to_bytes());

    let context = CiphertextCiphertextEqualityProofContext {
        first_pubkey: pod_first_pubkey,
        second_pubkey: pod_second_pubkey,
        first_ciphertext: pod_first_ciphertext,
        second_ciphertext: pod_second_ciphertext,
    };

    let mut transcript =
        Transcript::new_zk_elgamal_transcript(b"ciphertext-ciphertext-equality-instruction");

    let proof = CiphertextCiphertextEqualityProof::new(
        first_keypair,
        second_pubkey,
        first_ciphertext,
        second_ciphertext,
        second_opening,
        amount,
        &mut transcript,
    )
    .into();

    Ok(CiphertextCiphertextEqualityProofData { context, proof })
}

impl ZkProofData<CiphertextCiphertextEqualityProofContext>
    for CiphertextCiphertextEqualityProofData
{
    const PROOF_TYPE: ProofType = ProofType::CiphertextCiphertextEquality;

    fn context_data(&self) -> &CiphertextCiphertextEqualityProofContext {
        &self.context
    }
}

#[cfg(not(target_os = "solana"))]
impl VerifyZkProof for CiphertextCiphertextEqualityProofData {
    fn verify_proof(&self) -> Result<(), ProofVerificationError> {
        let mut transcript =
            Transcript::new_zk_elgamal_transcript(b"ciphertext-ciphertext-equality-instruction");

        let first_pubkey = self.context.first_pubkey.try_into()?;
        let second_pubkey = self.context.second_pubkey.try_into()?;
        let first_ciphertext = self.context.first_ciphertext.try_into()?;
        let second_ciphertext = self.context.second_ciphertext.try_into()?;
        let proof: CiphertextCiphertextEqualityProof = self.proof.try_into()?;

        proof
            .verify(
                &first_pubkey,
                &second_pubkey,
                &first_ciphertext,
                &second_ciphertext,
                &mut transcript,
            )
            .map_err(|e| e.into())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_ciphertext_ciphertext_instruction_correctness() {
        let first_keypair = ElGamalKeypair::new_rand();
        let second_keypair = ElGamalKeypair::new_rand();

        let amount: u64 = 0;
        let first_ciphertext = first_keypair.pubkey().encrypt(amount);

        let second_opening = PedersenOpening::new_rand();
        let second_ciphertext = second_keypair
            .pubkey()
            .encrypt_with(amount, &second_opening);

        let proof_data = build_ciphertext_ciphertext_equality_proof_data(
            &first_keypair,
            second_keypair.pubkey(),
            &first_ciphertext,
            &second_ciphertext,
            &second_opening,
            amount,
        )
        .unwrap();

        assert!(proof_data.verify_proof().is_ok());

        let amount: u64 = 55;
        let first_ciphertext = first_keypair.pubkey().encrypt(amount);

        let second_opening = PedersenOpening::new_rand();
        let second_ciphertext = second_keypair
            .pubkey()
            .encrypt_with(amount, &second_opening);

        let proof_data = build_ciphertext_ciphertext_equality_proof_data(
            &first_keypair,
            second_keypair.pubkey(),
            &first_ciphertext,
            &second_ciphertext,
            &second_opening,
            amount,
        )
        .unwrap();

        assert!(proof_data.verify_proof().is_ok());

        let amount = u64::MAX;
        let first_ciphertext = first_keypair.pubkey().encrypt(amount);

        let second_opening = PedersenOpening::new_rand();
        let second_ciphertext = second_keypair
            .pubkey()
            .encrypt_with(amount, &second_opening);

        let proof_data = build_ciphertext_ciphertext_equality_proof_data(
            &first_keypair,
            second_keypair.pubkey(),
            &first_ciphertext,
            &second_ciphertext,
            &second_opening,
            amount,
        )
        .unwrap();

        assert!(proof_data.verify_proof().is_ok());

        let amount_2 = 77_u64;
        let second_opening_2 = PedersenOpening::new_rand();
        let second_ciphertext_2 = second_keypair
            .pubkey()
            .encrypt_with(amount_2, &second_opening_2);

        // We try to prove equality between encryption of 55 and encryption of 77
        let result = build_ciphertext_ciphertext_equality_proof_data(
            &first_keypair,
            second_keypair.pubkey(),
            &first_ciphertext,
            &second_ciphertext_2,
            &second_opening_2,
            amount,
        );

        assert_eq!(result, Err(ProofGenerationError::InconsistentInput));
    }
}
