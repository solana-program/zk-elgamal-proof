//! The ciphertext validity sigma proof system.
//!
//! The ciphertext validity proof is defined with respect to a Pedersen commitment and two
//! decryption handles. The proof certifies that a given Pedersen commitment can be decrypted using
//! ElGamal private keys that are associated with each of the two decryption handles. To generate
//! the proof, a prover must provide the Pedersen opening associated with the commitment.
//!
//! This protocol reduces two `GroupedCiphertext2HandlesValidityProof` instances into a single
//! proof. The batching is achieved by compressing the two separate statements into one using a
//! random linear combination.
//!
//! The verifier provides a random challenge scalar `t` sampled from the transcript. The prover and
//! verifier then use this scalar to compute a linear combination of their respective inputs. A
//! single `GroupedCiphertext2HandlesValidityProof` is then generated and verified for this new
//! batched statement and witness.
//!
//! The protocol guarantees computational soundness (by the hardness of discrete log) and perfect
//! zero-knowledge in the random oracle model.

#[cfg(not(target_os = "solana"))]
use {
    crate::encryption::{
        elgamal::{DecryptHandle, ElGamalPubkey},
        grouped_elgamal::GroupedElGamalCiphertext,
        pedersen::{PedersenCommitment, PedersenOpening},
    },
    zeroize::Zeroize,
};
use {
    crate::{
        sigma_proofs::{
            errors::{SigmaProofVerificationError, ValidityProofVerificationError},
            grouped_ciphertext_validity::GroupedCiphertext2HandlesValidityProof,
        },
        transcript::TranscriptProtocol,
    },
    curve25519_dalek::{scalar::Scalar, traits::IsIdentity},
    merlin::Transcript,
};

/// Batched grouped ciphertext validity proof with two handles.
///
/// A batched grouped ciphertext validity proof certifies the validity of two instances of a
/// standard ciphertext validity proof. An instance of a standard validity proof consists of one
/// ciphertext and two decryption handles: `(commitment, first_handle, second_handle)`. An
/// instance of a batched ciphertext validity proof is a pair `(commitment_0,
/// first_handle_0, second_handle_0)` and `(commitment_1, first_handle_1,
/// second_handle_1)`. The proof certifies the analogous decryptable properties for each one of
/// these pairs of commitment and decryption handles.
#[allow(non_snake_case)]
#[derive(Clone)]
pub struct BatchedGroupedCiphertext2HandlesValidityProof(GroupedCiphertext2HandlesValidityProof);

#[allow(non_snake_case)]
#[cfg(not(target_os = "solana"))]
impl BatchedGroupedCiphertext2HandlesValidityProof {
    /// Creates a batched grouped ciphertext validity proof.
    ///
    /// The function simply batches the input openings and invokes the standard grouped ciphertext
    /// validity proof constructor.
    ///
    /// This function is randomized. It uses `OsRng` internally to generate random scalars.
    #[allow(clippy::too_many_arguments)]
    pub fn new<T: Into<Scalar>>(
        first_pubkey: &ElGamalPubkey,
        second_pubkey: &ElGamalPubkey,
        grouped_ciphertext_lo: &GroupedElGamalCiphertext<2>,
        grouped_ciphertext_hi: &GroupedElGamalCiphertext<2>,
        amount_lo: T,
        amount_hi: T,
        opening_lo: &PedersenOpening,
        opening_hi: &PedersenOpening,
        transcript: &mut Transcript,
    ) -> Self {
        Self::hash_context_into_transcript(
            first_pubkey,
            second_pubkey,
            grouped_ciphertext_lo,
            grouped_ciphertext_hi,
            transcript,
        );
        transcript.batched_grouped_ciphertext_validity_proof_domain_separator(2);

        let t = transcript.challenge_scalar(b"t");

        let mut batched_message = amount_lo.into() + amount_hi.into() * t;
        let batched_opening = opening_lo + &(opening_hi * &t);

        let proof = BatchedGroupedCiphertext2HandlesValidityProof(
            GroupedCiphertext2HandlesValidityProof::new_direct(
                first_pubkey,
                second_pubkey,
                batched_message,
                &batched_opening,
                transcript,
            ),
        );

        // zeroize all sensitive owned variables
        batched_message.zeroize();

        proof
    }

    /// Verifies a batched grouped ciphertext validity proof.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        self,
        first_pubkey: &ElGamalPubkey,
        second_pubkey: &ElGamalPubkey,
        grouped_ciphertext_lo: &GroupedElGamalCiphertext<2>,
        grouped_ciphertext_hi: &GroupedElGamalCiphertext<2>,
        transcript: &mut Transcript,
    ) -> Result<(), ValidityProofVerificationError> {
        // We reject if the first public key or the commitments are the identity point.
        // We allow the second public key to be an identity point as it is often the auditor's
        // public key in the token-2022 program that can be the identity.
        if first_pubkey.get_point().is_identity()
            || grouped_ciphertext_lo.commitment.get_point().is_identity()
            || grouped_ciphertext_hi.commitment.get_point().is_identity()
        {
            return Err(SigmaProofVerificationError::IdentityPoint.into());
        }

        Self::hash_context_into_transcript(
            first_pubkey,
            second_pubkey,
            grouped_ciphertext_lo,
            grouped_ciphertext_hi,
            transcript,
        );
        transcript.batched_grouped_ciphertext_validity_proof_domain_separator(2);

        let t = transcript.challenge_scalar(b"t");

        let commitment_lo = grouped_ciphertext_lo.commitment;
        let commitment_hi = grouped_ciphertext_hi.commitment;

        let first_handle_lo = grouped_ciphertext_lo.handles.first().unwrap();
        let first_handle_hi = grouped_ciphertext_hi.handles.first().unwrap();

        let second_handle_lo = grouped_ciphertext_lo.handles.get(1).unwrap();
        let second_handle_hi = grouped_ciphertext_hi.handles.get(1).unwrap();

        let batched_commitment = commitment_lo + commitment_hi * t;
        let first_batched_handle = first_handle_lo + first_handle_hi * t;
        let second_batched_handle = second_handle_lo + second_handle_hi * t;

        let batched_grouped_ciphertext = GroupedElGamalCiphertext {
            commitment: batched_commitment,
            handles: [first_batched_handle, second_batched_handle],
        };

        let BatchedGroupedCiphertext2HandlesValidityProof(validity_proof) = self;

        validity_proof.verify_direct(
            first_pubkey,
            second_pubkey,
            &batched_grouped_ciphertext,
            transcript,
        )
    }

    fn hash_context_into_transcript(
        first_pubkey: &ElGamalPubkey,
        second_pubkey: &ElGamalPubkey,
        grouped_ciphertext_lo: &GroupedElGamalCiphertext<2>,
        grouped_ciphertext_hi: &GroupedElGamalCiphertext<2>,
        transcript: &mut Transcript,
    ) {
        transcript.append_message(b"first-pubkey", &first_pubkey.to_bytes());
        transcript.append_message(b"second-pubkey", &second_pubkey.to_bytes());
        transcript.append_message(b"grouped-ciphertext-lo", &grouped_ciphertext_lo.to_bytes());
        transcript.append_message(b"grouped-ciphertext-hi", &grouped_ciphertext_hi.to_bytes());
    }

    pub fn to_bytes(&self) -> [u8; 160] {
        self.0.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidityProofVerificationError> {
        GroupedCiphertext2HandlesValidityProof::from_bytes(bytes).map(Self)
    }
}

#[cfg(test)]
mod test {
    use {
        super::*,
        crate::{
            encryption::{
                elgamal::ElGamalKeypair,
                pedersen::Pedersen,
                pod::{
                    elgamal::{PodDecryptHandle, PodElGamalPubkey},
                    grouped_elgamal::PodGroupedElGamalCiphertext2Handles,
                    pedersen::PodPedersenCommitment,
                },
            },
            sigma_proofs::pod::PodBatchedGroupedCiphertext2HandlesValidityProof,
        },
        std::str::FromStr,
    };

    #[test]
    fn test_batched_grouped_ciphertext_2_handles_validity_proof() {
        let first_keypair = ElGamalKeypair::new_rand();
        let first_pubkey = first_keypair.pubkey();

        let second_keypair = ElGamalKeypair::new_rand();
        let second_pubkey = second_keypair.pubkey();

        let amount_lo: u64 = 55;
        let amount_hi: u64 = 77;

        let (commitment_lo, open_lo) = Pedersen::new(amount_lo);
        let (commitment_hi, open_hi) = Pedersen::new(amount_hi);

        let first_handle_lo = first_pubkey.decrypt_handle(&open_lo);
        let first_handle_hi = first_pubkey.decrypt_handle(&open_hi);

        let second_handle_lo = second_pubkey.decrypt_handle(&open_lo);
        let second_handle_hi = second_pubkey.decrypt_handle(&open_hi);

        let grouped_ciphertext_lo = GroupedElGamalCiphertext {
            commitment: commitment_lo,
            handles: [first_handle_lo, second_handle_lo],
        };
        let grouped_ciphertext_hi = GroupedElGamalCiphertext {
            commitment: commitment_hi,
            handles: [first_handle_hi, second_handle_hi],
        };

        let mut prover_transcript = Transcript::new_zk_elgamal_transcript(b"Test");
        let mut verifier_transcript = Transcript::new_zk_elgamal_transcript(b"Test");

        let proof = BatchedGroupedCiphertext2HandlesValidityProof::new(
            first_pubkey,
            second_pubkey,
            &grouped_ciphertext_lo,
            &grouped_ciphertext_hi,
            amount_lo,
            amount_hi,
            &open_lo,
            &open_hi,
            &mut prover_transcript,
        );

        proof
            .verify(
                first_pubkey,
                second_pubkey,
                &grouped_ciphertext_lo,
                &grouped_ciphertext_hi,
                &mut verifier_transcript,
            )
            .unwrap();

        assert_eq!(
            prover_transcript.challenge_scalar(b"test"),
            verifier_transcript.challenge_scalar(b"test"),
        )
    }

    #[test]
    fn test_batched_grouped_ciphertext_2_handles_validity_proof_string() {
        let first_pubkey_str = "cvkvHnlr6h8V9V1Q2mGj5+XH6SBvJRR3dMdDYtgnpwk=";
        let pod_first_pubkey = PodElGamalPubkey::from_str(first_pubkey_str).unwrap();
        let first_pubkey: ElGamalPubkey = pod_first_pubkey.try_into().unwrap();

        let second_pubkey_str = "evcjLw8+v2mcWRisCCKXbjWVNRsC0JufOoSV5cR9ixg=";
        let pod_second_pubkey = PodElGamalPubkey::from_str(second_pubkey_str).unwrap();
        let second_pubkey: ElGamalPubkey = pod_second_pubkey.try_into().unwrap();

        let grouped_ciphertext_lo_str = "MsnlU3s9YjWFaC3IjIKS52yl41X1xH+mre0BbAwE2j3E28wjWQPZn4B4nM+eV0zgihHq7uUSY57a4l42HJRULIBlCR/8G2Wfuq63WVbBroxmRbbJzZFGgdpGVLoFA8Aw";
        let pod_grouped_ciphertext_lo =
            PodGroupedElGamalCiphertext2Handles::from_str(grouped_ciphertext_lo_str).unwrap();
        let grouped_ciphertext_lo: GroupedElGamalCiphertext<2> =
            pod_grouped_ciphertext_lo.try_into().unwrap();

        let grouped_ciphertext_hi_str = "2kpzTKaOoiNM/zZimt9g5uX60GFCes355lM4S2QvWx46YMpuGWoU5gG5G9hoCuY5T9PwGTiIQashf6mUFuulPWr0EYKatR7Q8dfyeFpJl2pdZ2Imwmf5LDqDUXSt9Zg3";
        let pod_grouped_ciphertext_hi =
            PodGroupedElGamalCiphertext2Handles::from_str(grouped_ciphertext_hi_str).unwrap();
        let grouped_ciphertext_hi: GroupedElGamalCiphertext<2> =
            pod_grouped_ciphertext_hi.try_into().unwrap();

        let proof_str = "GqVxS3sISd9hw3r0jDx3qwNFArLpiXMcySvtQqu5PSGoZDTtRgXMDiSEPSRoTER7/pjI/z2G8yNWYBMS6E28U8rnVCAS6k1K8anbrTF4n7TRmAac4CdpKCh8AZPzvi40kpWskl20Fogq8WPVf1r2i6nesQGTrMsKXH5j7ShC8QZbPtTn878eTdB7K9DNWFxGshxL8KzMh0dLMlj7IAJnAg==";
        let pod_proof =
            PodBatchedGroupedCiphertext2HandlesValidityProof::from_str(proof_str).unwrap();
        let proof: BatchedGroupedCiphertext2HandlesValidityProof = pod_proof.try_into().unwrap();

        let mut verifier_transcript = Transcript::new_zk_elgamal_transcript(b"Test");

        proof
            .verify(
                &first_pubkey,
                &second_pubkey,
                &grouped_ciphertext_lo,
                &grouped_ciphertext_hi,
                &mut verifier_transcript,
            )
            .unwrap();
    }
}
