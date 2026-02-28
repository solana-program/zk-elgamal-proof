//! The ciphertext-commitment equality proof instruction.
//!
//! A ciphertext-commitment equality proof is defined with respect to a twisted ElGamal ciphertext
//! and a Pedersen commitment. The proof certifies that a given ciphertext and a commitment pair
//! encrypts/encodes the same message. To generate the proof, a prover must provide the decryption
//! key for the first ciphertext and the Pedersen opening for the commitment.

use {
    crate::{
        encryption::pod::{
            elgamal::{PodElGamalCiphertext, PodElGamalPubkey},
            pedersen::PodPedersenCommitment,
        },
        sigma_proofs::pod::PodCiphertextCommitmentEqualityProof,
        zk_elgamal_proof_program::proof_data::{ProofType, ZkProofData},
    },
    bytemuck_derive::{Pod, Zeroable},
};
#[cfg(not(target_os = "solana"))]
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
            proof_data::VerifyZkProof,
        },
    },
    curve25519_dalek::scalar::Scalar,
    merlin::Transcript,
    std::convert::TryInto,
};
/// The instruction data that is needed for the
/// `ProofInstruction::VerifyCiphertextCommitmentEquality` instruction.
///
/// It includes the cryptographic proof as well as the context data information needed to verify
/// the proof.
#[derive(Clone, Copy, Pod, Zeroable, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct CiphertextCommitmentEqualityProofData {
    pub context: CiphertextCommitmentEqualityProofContext,
    pub proof: PodCiphertextCommitmentEqualityProof,
}

/// The context data needed to verify a ciphertext-commitment equality proof.
#[derive(Clone, Copy, Pod, Zeroable, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct CiphertextCommitmentEqualityProofContext {
    /// The ElGamal pubkey
    pub pubkey: PodElGamalPubkey, // 32 bytes

    /// The ciphertext encrypted under the ElGamal pubkey
    pub ciphertext: PodElGamalCiphertext, // 64 bytes

    /// The Pedersen commitment
    pub commitment: PodPedersenCommitment, // 32 bytes
}

#[cfg(not(target_os = "solana"))]
impl CiphertextCommitmentEqualityProofData {
    pub fn new(
        keypair: &ElGamalKeypair,
        ciphertext: &ElGamalCiphertext,
        commitment: &PedersenCommitment,
        opening: &PedersenOpening,
        amount: u64,
    ) -> Result<Self, ProofGenerationError> {
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
}

impl ZkProofData<CiphertextCommitmentEqualityProofContext>
    for CiphertextCommitmentEqualityProofData
{
    const PROOF_TYPE: ProofType = ProofType::CiphertextCommitmentEquality;

    fn context_data(&self) -> &CiphertextCommitmentEqualityProofContext {
        &self.context
    }
}

#[cfg(not(target_os = "solana"))]
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

        let proof_data = CiphertextCommitmentEqualityProofData::new(
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

        let result = CiphertextCommitmentEqualityProofData::new(
            &keypair,
            &ciphertext,
            &commitment_2,
            &opening_2,
            amount,
        );

        assert_eq!(result, Err(ProofGenerationError::InconsistentInput));
    }
}
