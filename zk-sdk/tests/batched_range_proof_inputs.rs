use solana_zk_sdk::{
    encryption::pedersen::{Pedersen, PedersenCommitment, PedersenOpening},
    zk_elgamal_proof_program::{
        errors::{ProofGenerationError, ProofVerificationError},
        VerifyZkProof,
    },
};

const AMOUNTS: [u64; 4] = [3, 7, 15, 31];

fn commitments_and_openings() -> ([PedersenCommitment; 4], [PedersenOpening; 4]) {
    let openings = std::array::from_fn(|_| PedersenOpening::new_rand());
    let commitments = std::array::from_fn(|i| Pedersen::with(AMOUNTS[i], &openings[i]));
    (commitments, openings)
}

// Exercise each public builder directly, including type inference at its call sites.
macro_rules! test_batched_range_proof_inputs {
    ($module:ident, $builder:ident, $total_bits:literal) => {
        mod $module {
            use {super::*, solana_zk_sdk::zk_elgamal_proof_program::$builder as build};

            const BIT_LENGTHS: [usize; 4] = [$total_bits / 4; 4];

            #[test]
            fn accepts_vector_inputs() {
                let (commitments, openings) = commitments_and_openings();
                let proof = build(
                    commitments.iter().collect(),
                    AMOUNTS.to_vec(),
                    BIT_LENGTHS.to_vec(),
                    openings.iter().collect(),
                )
                .unwrap();
                proof.verify_proof().unwrap();
            }

            #[test]
            fn rejects_invalid_inputs() {
                let (commitments, openings) = commitments_and_openings();
                assert_eq!(
                    build(
                        commitments[..3].iter().collect(),
                        AMOUNTS.to_vec(),
                        BIT_LENGTHS.to_vec(),
                        openings.iter().collect(),
                    )
                    .unwrap_err(),
                    ProofGenerationError::IllegalCommitmentLength,
                );
                assert_eq!(
                    build(
                        commitments.iter().collect(),
                        AMOUNTS[..3].to_vec(),
                        BIT_LENGTHS.to_vec(),
                        openings.iter().collect(),
                    )
                    .unwrap_err(),
                    ProofGenerationError::IllegalCommitmentLength,
                );
                assert_eq!(
                    build(
                        commitments.iter().collect(),
                        AMOUNTS.to_vec(),
                        BIT_LENGTHS.to_vec(),
                        openings[..3].iter().collect(),
                    )
                    .unwrap_err(),
                    ProofGenerationError::IllegalCommitmentLength,
                );
                assert_eq!(
                    build(
                        commitments.iter().collect(),
                        AMOUNTS.to_vec(),
                        BIT_LENGTHS[..3].to_vec(),
                        openings.iter().collect(),
                    )
                    .unwrap_err(),
                    ProofGenerationError::IllegalAmountBitLength,
                );
                assert_eq!(
                    build(vec![], vec![], vec![], vec![]).unwrap_err(),
                    ProofGenerationError::IllegalAmountBitLength,
                );

                let (commitment, opening) = Pedersen::new(1_u64);
                let mut too_many_bit_lengths = vec![$total_bits / 9; 9];
                too_many_bit_lengths[8] = $total_bits / 9 + $total_bits % 9;
                assert_eq!(
                    build(
                        vec![&commitment; 9],
                        vec![1; 9],
                        too_many_bit_lengths,
                        vec![&opening; 9],
                    )
                    .unwrap_err(),
                    ProofGenerationError::IllegalCommitmentLength,
                );

                // Keep the total valid so that rejection depends on the zero component.
                assert!(matches!(
                    build(
                        vec![&commitment; 5],
                        vec![1; 5],
                        vec![
                            0,
                            $total_bits / 4,
                            $total_bits / 4,
                            $total_bits / 4,
                            $total_bits / 4
                        ],
                        vec![&opening; 5],
                    ),
                    Err(ProofGenerationError::RangeProof(_)),
                ));

                let mut identity_commitments = commitments;
                identity_commitments[0] = PedersenCommitment::default();
                assert_eq!(
                    build(
                        identity_commitments.iter().collect(),
                        AMOUNTS.to_vec(),
                        BIT_LENGTHS.to_vec(),
                        openings.iter().collect(),
                    )
                    .unwrap_err(),
                    ProofGenerationError::InvalidCommitment,
                );
            }

            #[test]
            fn rejects_invalid_context_and_padding() {
                let (commitments, openings) = commitments_and_openings();
                let proof = build(
                    commitments.iter().collect(),
                    AMOUNTS.to_vec(),
                    BIT_LENGTHS.to_vec(),
                    openings.iter().collect(),
                )
                .unwrap();
                proof.verify_proof().unwrap();

                for bit_length in [0, 65] {
                    let mut invalid = proof;
                    invalid.context.bit_lengths[0] = bit_length;
                    assert_eq!(
                        invalid.verify_proof().unwrap_err(),
                        ProofVerificationError::IllegalAmountBitLength,
                    );
                }

                let mut invalid = proof;
                invalid.context.commitments[5] = proof.context.commitments[0];
                assert_eq!(
                    invalid.verify_proof().unwrap_err(),
                    ProofVerificationError::ProofContext,
                );

                let mut invalid = proof;
                invalid.context.bit_lengths[4] = 1;
                assert_eq!(
                    invalid.verify_proof().unwrap_err(),
                    ProofVerificationError::ProofContext,
                );
            }
        }
    };
}

test_batched_range_proof_inputs!(u64_proof, build_batched_range_proof_u64_data, 64);
test_batched_range_proof_inputs!(u128_proof, build_batched_range_proof_u128_data, 128);
test_batched_range_proof_inputs!(u256_proof, build_batched_range_proof_u256_data, 256);
