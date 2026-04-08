pub mod batched_range_proof_u128;
pub mod batched_range_proof_u256;
pub mod batched_range_proof_u64;

use {
    crate::{
        encryption::pedersen::{PedersenCommitment, PedersenOpening},
        transcript::TranscriptProtocol,
        zk_elgamal_proof_program::errors::{ProofGenerationError, ProofVerificationError},
    },
    bytemuck::{bytes_of, Zeroable},
    curve25519::traits::IsIdentity,
    merlin::Transcript,
    solana_zk_elgamal_proof_interface::proof_data::{BatchedRangeProofContext, MAX_COMMITMENTS},
    solana_zk_sdk_pod::encryption::pedersen::PodPedersenCommitment,
    std::convert::TryInto,
};
pub use {batched_range_proof_u128::*, batched_range_proof_u256::*, batched_range_proof_u64::*};

/// A bit length in a batched range proof must be at most 64.
///
/// Although the batched proof supports a total of 256 bits, individual components are restricted
/// to `u64` amounts (64 bits).
const MAX_SINGLE_BIT_LENGTH: usize = 64;

pub(crate) fn batched_range_proof_transcript(context: &BatchedRangeProofContext) -> Transcript {
    let mut transcript = Transcript::new_zk_elgamal_transcript(b"batched-range-proof-instruction");
    transcript.append_message(b"commitments", bytes_of(&context.commitments));
    transcript.append_message(b"bit-lengths", bytes_of(&context.bit_lengths));
    transcript
}

#[allow(non_snake_case)]
pub(crate) fn build_batched_range_proof_context(
    commitments: &[&PedersenCommitment],
    amounts: &[u64],
    bit_lengths: &[usize],
    openings: &[&PedersenOpening],
) -> Result<BatchedRangeProofContext, ProofGenerationError> {
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

pub(crate) fn verify_batched_range_proof_context(
    context: &BatchedRangeProofContext,
) -> Result<(Vec<PedersenCommitment>, Vec<usize>), ProofVerificationError> {
    let commitments = context
        .commitments
        .into_iter()
        .take_while(|commitment| *commitment != PodPedersenCommitment::zeroed())
        .map(|commitment| commitment.try_into())
        .collect::<Result<Vec<PedersenCommitment>, _>>()
        .map_err(|_| ProofVerificationError::ProofContext)?;

    let bit_lengths: Vec<_> = context
        .bit_lengths
        .into_iter()
        .take(commitments.len())
        .map(|bit_length| bit_length as usize)
        .collect();

    // Ensure at least one commitment exists
    if commitments.is_empty() {
        return Err(ProofVerificationError::IllegalCommitmentLength);
    }

    // Validate bit lengths (must be > 0 and <= MAX_SINGLE_BIT_LENGTH)
    if bit_lengths
        .iter()
        .any(|&bit_length| bit_length == 0 || bit_length > MAX_SINGLE_BIT_LENGTH)
    {
        return Err(ProofVerificationError::IllegalAmountBitLength);
    }

    // Ensure that all ignored data in the context (the "tail") is strictly zero.
    let len = commitments.len();
    let commitments_padding_valid = context.commitments[len..]
        .iter()
        .all(|commitment| *commitment == PodPedersenCommitment::zeroed());

    let bit_lengths_padding_valid = context.bit_lengths[len..]
        .iter()
        .all(|&bit_length| bit_length == 0);

    if !commitments_padding_valid || !bit_lengths_padding_valid {
        return Err(ProofVerificationError::ProofContext);
    }

    Ok((commitments, bit_lengths))
}
