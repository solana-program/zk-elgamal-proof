use {
    crate::{
        encryption::pedersen::{PedersenCommitment, PedersenOpening},
        range_proof::range::RangeProof,
        zk_elgamal_proof_program::{
            batched_range_proof::{
                batched_range_proof_transcript, build_batched_range_proof_context,
                verify_batched_range_proof_context, MAX_COMMITMENTS,
            },
            errors::{ProofGenerationError, ProofVerificationError},
            VerifyZkProof,
        },
    },
    solana_zk_elgamal_proof_interface::proof_data::BatchedRangeProofU128Data,
    std::{borrow::Borrow, convert::TryInto},
};

/// Builds a batched range proof with a total bit length of 128.
///
/// Inputs may be vectors, arrays, or slices. Commitments and openings may contain
/// owned values or references. Arrays and slices avoid allocating input vectors;
/// proof generation still allocates internally.
///
/// All inputs must have the same length, with at most eight commitments. Each bit
/// length must be between 1 and 64, and their sum must be 128.
///
/// See [`super::build_batched_range_proof_u64_data`] for an example and notes on
/// collection type inference.
pub fn build_batched_range_proof_u128_data<C, PC, A, B, O, PO>(
    commitments: C,
    amounts: A,
    bit_lengths: B,
    openings: O,
) -> Result<BatchedRangeProofU128Data, ProofGenerationError>
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

    // the sum of the bit lengths must be 128
    let batched_bit_length = bit_lengths
        .iter()
        .try_fold(0_usize, |acc, &x| acc.checked_add(x))
        .ok_or(ProofGenerationError::IllegalAmountBitLength)?;

    // `u128::BITS` is 128, which fits in a single byte and should not overflow to `usize` for
    // an overwhelming number of platforms. However, to be extra cautious, use `try_from` and
    // `unwrap` here. A simple case `u128::BITS as usize` can silently overflow.
    let expected_bit_length = usize::try_from(u128::BITS).unwrap();
    if batched_bit_length != expected_bit_length {
        return Err(ProofGenerationError::IllegalAmountBitLength);
    }

    let context = build_batched_range_proof_context(commitments, amounts, bit_lengths, openings)?;

    let mut transcript = batched_range_proof_transcript(&context);
    let proof = RangeProof::new(amounts, bit_lengths, openings, &mut transcript)?
        .try_into()
        .map_err(|_| ProofGenerationError::ProofLength)?;

    Ok(BatchedRangeProofU128Data { context, proof })
}

impl VerifyZkProof for BatchedRangeProofU128Data {
    fn verify_proof(&self) -> Result<(), ProofVerificationError> {
        let (commitments, bit_lengths) = verify_batched_range_proof_context(&self.context)?;
        let num_commitments = commitments.len();

        if num_commitments > MAX_COMMITMENTS {
            return Err(ProofVerificationError::IllegalCommitmentLength);
        }

        let batched_bit_length = bit_lengths
            .iter()
            .try_fold(0_usize, |acc, &x| acc.checked_add(x))
            .ok_or(ProofVerificationError::ProofContext)?;

        let expected_bit_length = usize::try_from(u128::BITS).unwrap();
        if batched_bit_length != expected_bit_length {
            return Err(ProofVerificationError::IllegalCommitmentLength);
        }

        let mut transcript = batched_range_proof_transcript(&self.context);
        let proof: RangeProof = self.proof.try_into()?;

        proof
            .verify(commitments, bit_lengths, &mut transcript)
            .map_err(|e| e.into())
    }
}

#[cfg(test)]
mod test {
    use {
        super::*,
        crate::{
            encryption::pedersen::Pedersen, range_proof::errors::RangeProofVerificationError,
            zk_elgamal_proof_program::errors::ProofVerificationError,
        },
    };

    #[test]
    fn test_batched_range_proof_u128_instruction_correctness() {
        let amount_1 = 65535_u64;
        let amount_2 = 77_u64;
        let amount_3 = 99_u64;
        let amount_4 = 99_u64;
        let amount_5 = 11_u64;
        let amount_6 = 33_u64;
        let amount_7 = 99_u64;
        let amount_8 = 99_u64;

        let (commitment_1, opening_1) = Pedersen::new(amount_1);
        let (commitment_2, opening_2) = Pedersen::new(amount_2);
        let (commitment_3, opening_3) = Pedersen::new(amount_3);
        let (commitment_4, opening_4) = Pedersen::new(amount_4);
        let (commitment_5, opening_5) = Pedersen::new(amount_5);
        let (commitment_6, opening_6) = Pedersen::new(amount_6);
        let (commitment_7, opening_7) = Pedersen::new(amount_7);
        let (commitment_8, opening_8) = Pedersen::new(amount_8);

        let proof_data = build_batched_range_proof_u128_data(
            [
                &commitment_1,
                &commitment_2,
                &commitment_3,
                &commitment_4,
                &commitment_5,
                &commitment_6,
                &commitment_7,
                &commitment_8,
            ],
            [
                amount_1, amount_2, amount_3, amount_4, amount_5, amount_6, amount_7, amount_8,
            ],
            [16, 16, 16, 16, 16, 16, 16, 16],
            [
                &opening_1, &opening_2, &opening_3, &opening_4, &opening_5, &opening_6, &opening_7,
                &opening_8,
            ],
        )
        .unwrap();

        assert!(proof_data.verify_proof().is_ok());

        let amount_1 = 65536_u64; // not representable as a 16-bit number
        let amount_2 = 77_u64;
        let amount_3 = 99_u64;
        let amount_4 = 99_u64;
        let amount_5 = 11_u64;
        let amount_6 = 33_u64;
        let amount_7 = 99_u64;
        let amount_8 = 99_u64;

        let (commitment_1, opening_1) = Pedersen::new(amount_1);
        let (commitment_2, opening_2) = Pedersen::new(amount_2);
        let (commitment_3, opening_3) = Pedersen::new(amount_3);
        let (commitment_4, opening_4) = Pedersen::new(amount_4);
        let (commitment_5, opening_5) = Pedersen::new(amount_5);
        let (commitment_6, opening_6) = Pedersen::new(amount_6);
        let (commitment_7, opening_7) = Pedersen::new(amount_7);
        let (commitment_8, opening_8) = Pedersen::new(amount_8);

        let proof_data = build_batched_range_proof_u128_data(
            [
                &commitment_1,
                &commitment_2,
                &commitment_3,
                &commitment_4,
                &commitment_5,
                &commitment_6,
                &commitment_7,
                &commitment_8,
            ],
            [
                amount_1, amount_2, amount_3, amount_4, amount_5, amount_6, amount_7, amount_8,
            ],
            [16, 16, 16, 16, 16, 16, 16, 16],
            [
                &opening_1, &opening_2, &opening_3, &opening_4, &opening_5, &opening_6, &opening_7,
                &opening_8,
            ],
        )
        .unwrap();

        assert_eq!(
            proof_data.verify_proof().unwrap_err(),
            ProofVerificationError::RangeProof(RangeProofVerificationError::AlgebraicRelation),
        );
    }
}
