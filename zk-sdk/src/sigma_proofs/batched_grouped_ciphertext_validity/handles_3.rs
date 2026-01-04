//! The batched ciphertext with 3 handles validity sigma proof system.
//!
//! A batched grouped ciphertext validity proof certifies the validity of two instances of a
//! standard grouped ciphertext validity proof. An instance of a standard grouped ciphertext
//! with 3 handles validity proof consists of one ciphertext and three decryption handles:
//! `(commitment, first_handle, second_handle, third_handle)`. An instance of a batched
//! grouped ciphertext with 3 handles validity proof consist of a pair of `(commitment_0,
//! first_handle_0, second_handle_0, third_handle_0)` and `(commitment_1, first_handle_1,
//! second_handle_1, third_handle_1)`. The proof certifies the anagolous decryptable
//! properties for each one of these pairs of commitment and decryption handles.
//!
//! This protocol reduces two `GroupedCiphertext3HandlesValidityProof` instances into a single
//! proof. The batching is achieved by compressing the two separate statements into one using a
//! random linear combination.
//!
//! The verifier provides a random challenge scalar `t` sampled from the transcript. The prover and
//! verifier then use this scalar to compute a linear combination of their respective inputs. A
//! single `GroupedCiphertext3HandlesValidityProof` is then generated and verified for this new
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
            errors::ValidityProofVerificationError,
            grouped_ciphertext_validity::GroupedCiphertext3HandlesValidityProof,
        },
        transcript::TranscriptProtocol,
        UNIT_LEN,
    },
    curve25519_dalek::scalar::Scalar,
    merlin::Transcript,
};

/// Byte length of a batched grouped ciphertext validity proof for 3 handles
#[allow(dead_code)]
const BATCHED_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_PROOF_LEN: usize = UNIT_LEN * 6;

/// Batched grouped ciphertext validity proof with two handles.
#[allow(non_snake_case)]
#[derive(Clone)]
pub struct BatchedGroupedCiphertext3HandlesValidityProof(GroupedCiphertext3HandlesValidityProof);

#[allow(non_snake_case)]
#[allow(dead_code)]
#[cfg(not(target_os = "solana"))]
impl BatchedGroupedCiphertext3HandlesValidityProof {
    /// Creates a batched grouped ciphertext validity proof.
    ///
    /// The function simply batches the input openings and invokes the standard grouped ciphertext
    /// validity proof constructor.
    #[allow(clippy::too_many_arguments)]
    pub fn new<T: Into<Scalar>>(
        first_pubkey: &ElGamalPubkey,
        second_pubkey: &ElGamalPubkey,
        third_pubkey: &ElGamalPubkey,
        grouped_ciphertext_lo: &GroupedElGamalCiphertext<3>,
        grouped_ciphertext_hi: &GroupedElGamalCiphertext<3>,
        amount_lo: T,
        amount_hi: T,
        opening_lo: &PedersenOpening,
        opening_hi: &PedersenOpening,
        transcript: &mut Transcript,
    ) -> Self {
        Self::hash_context_into_transcript(
            first_pubkey,
            second_pubkey,
            third_pubkey,
            grouped_ciphertext_lo,
            grouped_ciphertext_hi,
            transcript,
        );
        transcript.batched_grouped_ciphertext_validity_proof_domain_separator(3);

        let t = transcript.challenge_scalar(b"t");

        let mut batched_message = amount_lo.into() + amount_hi.into() * t;
        let batched_opening = opening_lo + &(opening_hi * &t);

        let proof = BatchedGroupedCiphertext3HandlesValidityProof(
            GroupedCiphertext3HandlesValidityProof::new_direct(
                first_pubkey,
                second_pubkey,
                third_pubkey,
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
    ///
    /// This function is randomized. It uses `OsRng` internally to generate random scalars.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        self,
        first_pubkey: &ElGamalPubkey,
        second_pubkey: &ElGamalPubkey,
        third_pubkey: &ElGamalPubkey,
        grouped_ciphertext_lo: &GroupedElGamalCiphertext<3>,
        grouped_ciphertext_hi: &GroupedElGamalCiphertext<3>,
        transcript: &mut Transcript,
    ) -> Result<(), ValidityProofVerificationError> {
        Self::hash_context_into_transcript(
            first_pubkey,
            second_pubkey,
            third_pubkey,
            grouped_ciphertext_lo,
            grouped_ciphertext_hi,
            transcript,
        );
        transcript.batched_grouped_ciphertext_validity_proof_domain_separator(3);

        let t = transcript.challenge_scalar(b"t");

        let commitment_lo = grouped_ciphertext_lo.commitment;
        let commitment_hi = grouped_ciphertext_hi.commitment;

        let first_handle_lo = grouped_ciphertext_lo.handles.first().unwrap();
        let first_handle_hi = grouped_ciphertext_hi.handles.first().unwrap();

        let second_handle_lo = grouped_ciphertext_lo.handles.get(1).unwrap();
        let second_handle_hi = grouped_ciphertext_hi.handles.get(1).unwrap();

        let third_handle_lo = grouped_ciphertext_lo.handles.get(2).unwrap();
        let third_handle_hi = grouped_ciphertext_hi.handles.get(2).unwrap();

        let batched_commitment = commitment_lo + commitment_hi * t;
        let first_batched_handle = first_handle_lo + first_handle_hi * t;
        let second_batched_handle = second_handle_lo + second_handle_hi * t;
        let third_batched_handle = third_handle_lo + third_handle_hi * t;

        let batched_grouped_ciphertext = GroupedElGamalCiphertext {
            commitment: batched_commitment,
            handles: [
                first_batched_handle,
                second_batched_handle,
                third_batched_handle,
            ],
        };

        let BatchedGroupedCiphertext3HandlesValidityProof(validity_proof) = self;

        validity_proof.verify_direct(
            first_pubkey,
            second_pubkey,
            third_pubkey,
            &batched_grouped_ciphertext,
            transcript,
        )
    }

    fn hash_context_into_transcript(
        first_pubkey: &ElGamalPubkey,
        second_pubkey: &ElGamalPubkey,
        third_pubkey: &ElGamalPubkey,
        grouped_ciphertext_lo: &GroupedElGamalCiphertext<3>,
        grouped_ciphertext_hi: &GroupedElGamalCiphertext<3>,
        transcript: &mut Transcript,
    ) {
        transcript.append_message(b"first-pubkey", &first_pubkey.to_bytes());
        transcript.append_message(b"second-pubkey", &second_pubkey.to_bytes());
        transcript.append_message(b"third-pubkey", &third_pubkey.to_bytes());
        transcript.append_message(b"grouped-ciphertext-lo", &grouped_ciphertext_lo.to_bytes());
        transcript.append_message(b"grouped-ciphertext-hi", &grouped_ciphertext_hi.to_bytes());
    }

    pub fn to_bytes(&self) -> [u8; BATCHED_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_PROOF_LEN] {
        self.0.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidityProofVerificationError> {
        GroupedCiphertext3HandlesValidityProof::from_bytes(bytes).map(Self)
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
                    grouped_elgamal::PodGroupedElGamalCiphertext3Handles,
                    pedersen::PodPedersenCommitment,
                },
            },
            sigma_proofs::pod::PodBatchedGroupedCiphertext3HandlesValidityProof,
        },
        std::str::FromStr,
    };

    #[test]
    fn test_batched_grouped_ciphertext_3_handles_validity_proof() {
        let first_keypair = ElGamalKeypair::new_rand();
        let first_pubkey = first_keypair.pubkey();

        let second_keyapir = ElGamalKeypair::new_rand();
        let second_pubkey = second_keyapir.pubkey();

        let third_keypair = ElGamalKeypair::new_rand();
        let third_pubkey = third_keypair.pubkey();

        let amount_lo: u64 = 55;
        let amount_hi: u64 = 77;

        let (commitment_lo, open_lo) = Pedersen::new(amount_lo);
        let (commitment_hi, open_hi) = Pedersen::new(amount_hi);

        let first_handle_lo = first_pubkey.decrypt_handle(&open_lo);
        let first_handle_hi = first_pubkey.decrypt_handle(&open_hi);

        let second_handle_lo = second_pubkey.decrypt_handle(&open_lo);
        let second_handle_hi = second_pubkey.decrypt_handle(&open_hi);

        let third_handle_lo = third_pubkey.decrypt_handle(&open_lo);
        let third_handle_hi = third_pubkey.decrypt_handle(&open_hi);

        let grouped_ciphertext_lo = GroupedElGamalCiphertext {
            commitment: commitment_lo,
            handles: [first_handle_lo, second_handle_lo, third_handle_lo],
        };
        let grouped_ciphertext_hi = GroupedElGamalCiphertext {
            commitment: commitment_hi,
            handles: [first_handle_hi, second_handle_hi, third_handle_hi],
        };

        let mut prover_transcript = Transcript::new(b"Test");
        let mut verifier_transcript = Transcript::new(b"Test");

        let proof = BatchedGroupedCiphertext3HandlesValidityProof::new(
            first_pubkey,
            second_pubkey,
            third_pubkey,
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
                third_pubkey,
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
    fn test_batched_grouped_ciphertext_3_handles_validity_proof_string() {
        let first_pubkey_str = "wHNY5XvUo78IXLa1cUlUihKFtGc4MBYNa2owsDMUeGY=";
        let pod_first_pubkey = PodElGamalPubkey::from_str(first_pubkey_str).unwrap();
        let first_pubkey: ElGamalPubkey = pod_first_pubkey.try_into().unwrap();

        let second_pubkey_str = "gFcPVz9K6hrmZaIIxZCzUReAaslmoeG+iYgqgAjYIik=";
        let pod_second_pubkey = PodElGamalPubkey::from_str(second_pubkey_str).unwrap();
        let second_pubkey: ElGamalPubkey = pod_second_pubkey.try_into().unwrap();

        let third_pubkey_str = "BDq8H0zNhWN4a33SbBS9VeKkaPHH+XpEuOtQKmVoHhY=";
        let pod_third_pubkey = PodElGamalPubkey::from_str(third_pubkey_str).unwrap();
        let third_pubkey: ElGamalPubkey = pod_third_pubkey.try_into().unwrap();

        let grouped_ciphertext_lo_str = "iKQ6Z39F6m4aax7LZT6fOSj4zCVRtymxFoUHnZ5y3ypWwQDK5BwI0tB+T/D+GKe9xL2RLLCp3a0DFh6Wa3HUMQ5TGnwZSqpqvx4+G9LUVYhLsIJgkm9+ugn8W2xI7IsgtKVtI25e728L3RuNlVuPTFpo6JBpeQu6JVKLFlND+Cg=";
        let pod_grouped_ciphertext_lo =
            PodGroupedElGamalCiphertext3Handles::from_str(grouped_ciphertext_lo_str).unwrap();
        let grouped_ciphertext_lo: GroupedElGamalCiphertext<3> =
            pod_grouped_ciphertext_lo.try_into().unwrap();

        let grouped_ciphertext_hi_str = "XIMFG7lp3lvF/6AhQPdnKiNITBBZFC18ldeZ8WcH9Hvan3Af1pmZKpCGYNmVq6o08rdp/GVLsousKle927xgJORqagQIJJRI9m3ycxsNnVNQp3xH6j2fFCTMGV1WRP4XJuS9DLkByIqDaKZzAJX1NiHCoQr32W9Pn+aHVo5d+Co=";
        let pod_grouped_ciphertext_hi =
            PodGroupedElGamalCiphertext3Handles::from_str(grouped_ciphertext_hi_str).unwrap();
        let grouped_ciphertext_hi: GroupedElGamalCiphertext<3> =
            pod_grouped_ciphertext_hi.try_into().unwrap();

        let proof_str = "Xuc6mdJ9uwShYmmxOti6mkyYsL7sbvoAQGCZabm6e2wGeIPORDtsQt1s4lnEtPodoFGBOjw/GH7qNtwcTBewWnrvfRA7ZzYbb1kTO7NfCthxunu7YQ9S3kemdIJlYKM3aoYkJp7/vLm7FE6Tuhr128I9nYIUcrYoRIuDVSMeTHpMBaLkfKHJGI95IPiCBHWtE0KeNKZLWUpM/CFdELJECNDJ68dG169GKLANMQh8rxMIgHyasVuG/bP11JAvgAwF";
        let pod_proof =
            PodBatchedGroupedCiphertext3HandlesValidityProof::from_str(proof_str).unwrap();
        let proof: BatchedGroupedCiphertext3HandlesValidityProof = pod_proof.try_into().unwrap();

        let mut verifier_transcript = Transcript::new(b"Test");

        proof
            .verify(
                &first_pubkey,
                &second_pubkey,
                &third_pubkey,
                &grouped_ciphertext_lo,
                &grouped_ciphertext_hi,
                &mut verifier_transcript,
            )
            .unwrap();
    }
}
