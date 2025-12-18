//! The batched range proof instructions.
//!
//! A batched range proof is a cryptographic method that proves a set of committed values
//! fall within specified bit-ranges, without revealing the values themselves. It is more
//! efficient than verifying individual range proofs for each commitment.
//!
//! This module provides three instructions for batched range proofs, each corresponding to a
//! different total bit length:
//! - `VerifyBatchedRangeProof64`: For proofs where the sum of bit lengths is 64.
//! - `VerifyBatchedRangeProof128`: For proofs where the sum of bit lengths is 128.
//! - `VerifyBatchedRangeProof256`: For proofs where the sum of bit lengths is 256.
//!
//! For example, to generate a batched range proof for a sequence of commitments `[C_1, C_2, C_3]`
//! with corresponding bit-lengths `[32, 32, 64]`, one must use `VerifyBatchedRangeProof128`,
//! since the sum of bit-lengths is `32 + 32 + 64 = 128`.
//!
//! The maximum number of commitments that can be batched together is fixed at 8. Each individual
//! bit length `n_i` must be at most 128.

pub mod batched_range_proof_u128;
pub mod batched_range_proof_u256;
pub mod batched_range_proof_u64;

use crate::encryption::pod::pedersen::PodPedersenCommitment;
#[cfg(not(target_os = "solana"))]
use {
    crate::{
        encryption::pedersen::{PedersenCommitment, PedersenOpening},
        zk_elgamal_proof_program::errors::{ProofGenerationError, ProofVerificationError},
    },
    bytemuck::{bytes_of, Zeroable},
    curve25519_dalek::traits::IsIdentity,
    merlin::Transcript,
    std::{borrow::Borrow, convert::TryInto},
};

/// The maximum number of Pedersen commitments that can be processed in a single batched range proof.
const MAX_COMMITMENTS: usize = 8;

/// A bit length in a batched range proof must be at most 128.
///
/// A 256-bit range proof on a single Pedersen commitment is meaningless and hence enforce an upper
/// bound as the largest power-of-two number less than 256.
#[cfg(not(target_os = "solana"))]
const MAX_SINGLE_BIT_LENGTH: usize = 128;

/// The context data needed to verify a range-proof for a Pedersen committed value.
///
/// This struct holds the public information that a batched range proof certifies. It includes the
/// Pedersen commitments and their corresponding bit lengths. This context is shared by all
/// `VerifyBatchedRangeProof{N}` instructions.
#[derive(Clone, Copy, bytemuck_derive::Pod, bytemuck_derive::Zeroable)]
#[repr(C)]
pub struct BatchedRangeProofContext {
    pub commitments: [PodPedersenCommitment; MAX_COMMITMENTS],
    pub bit_lengths: [u8; MAX_COMMITMENTS],
}

#[allow(non_snake_case)]
#[cfg(not(target_os = "solana"))]
impl BatchedRangeProofContext {
    fn new_transcript(&self) -> Transcript {
        let mut transcript = Transcript::new(b"batched-range-proof-instruction");
        transcript.append_message(b"commitments", bytes_of(&self.commitments));
        transcript.append_message(b"bit-lengths", bytes_of(&self.bit_lengths));
        transcript
    }

    fn new<C, PC, A, B, O, PO>(
        commitments: C,
        amounts: A,
        bit_lengths: B,
        openings: O,
    ) -> Result<Self, ProofGenerationError>
    where
        C: AsRef<[PC]>,
        PC: Borrow<PedersenCommitment>,
        A: AsRef<[u64]>,
        B: AsRef<[usize]>,
        O: AsRef<[PO]>,
        PO: Borrow<PedersenOpening>,
    {
        let commitments = commitments.as_ref();
        let amounts = amounts.as_ref();
        let bit_lengths = bit_lengths.as_ref();
        let openings = openings.as_ref();

        // the number of commitments is capped at 8
        let num_commitments = commitments.len();
        if num_commitments > MAX_COMMITMENTS
            || num_commitments != amounts.len()
            || num_commitments != bit_lengths.len()
            || num_commitments != openings.len()
        {
            return Err(ProofGenerationError::IllegalCommitmentLength);
        }

        let mut pod_commitments = [PodPedersenCommitment::zeroed(); MAX_COMMITMENTS];
        for (i, commitment) in commitments.iter().enumerate() {
            let commitment = commitment.borrow();
            // all-zero commitment is invalid
            //
            // this check only exists in the prover logic to enforce safe practice
            // identity commitments are not rejected by range proof verification logic itself
            if commitment.get_point().is_identity() {
                return Err(ProofGenerationError::InvalidCommitment);
            }
            pod_commitments[i] = PodPedersenCommitment(commitment.to_bytes());
        }

        let mut pod_bit_lengths = [0; MAX_COMMITMENTS];
        for (i, bit_length) in bit_lengths.iter().enumerate() {
            pod_bit_lengths[i] = (*bit_length)
                .try_into()
                .map_err(|_| ProofGenerationError::IllegalAmountBitLength)?;
        }

        Ok(BatchedRangeProofContext {
            commitments: pod_commitments,
            bit_lengths: pod_bit_lengths,
        })
    }
}

#[cfg(not(target_os = "solana"))]
impl TryInto<(Vec<PedersenCommitment>, Vec<usize>)> for BatchedRangeProofContext {
    type Error = ProofVerificationError;

    fn try_into(self) -> Result<(Vec<PedersenCommitment>, Vec<usize>), Self::Error> {
        let commitments = self
            .commitments
            .into_iter()
            .take_while(|commitment| *commitment != PodPedersenCommitment::zeroed())
            .map(|commitment| commitment.try_into())
            .collect::<Result<Vec<PedersenCommitment>, _>>()
            .map_err(|_| ProofVerificationError::ProofContext)?;

        let bit_lengths: Vec<_> = self
            .bit_lengths
            .into_iter()
            .take(commitments.len())
            .map(|bit_length| bit_length as usize)
            .collect();

        Ok((commitments, bit_lengths))
    }
}
