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
            fn accepts_vectors_arrays_and_slices() {
                let (commitments, openings) = commitments_and_openings();
                let commitment_refs = commitments.each_ref();
                let opening_refs = openings.each_ref();

                let proofs = [
                    // Preserve the original Vec<&T> calling convention.
                    build(
                        commitments.iter().collect::<Vec<_>>(),
                        AMOUNTS.to_vec(),
                        BIT_LENGTHS.to_vec(),
                        openings.iter().collect::<Vec<_>>(),
                    )
                    .unwrap(),
                    build(
                        commitments.as_slice(),
                        AMOUNTS.as_slice(),
                        BIT_LENGTHS.as_slice(),
                        openings.as_slice(),
                    )
                    .unwrap(),
                    build(
                        commitment_refs.as_slice(),
                        AMOUNTS.as_slice(),
                        BIT_LENGTHS.as_slice(),
                        opening_refs.as_slice(),
                    )
                    .unwrap(),
                    build(commitments, AMOUNTS, BIT_LENGTHS, openings.clone()).unwrap(),
                    build(
                        Vec::from(commitments),
                        Vec::from(AMOUNTS),
                        Vec::from(BIT_LENGTHS),
                        Vec::from(openings),
                    )
                    .unwrap(),
                ];

                let expected_context = proofs[0].context;
                for proof in proofs {
                    assert_eq!(proof.context, expected_context);
                    proof.verify_proof().unwrap();
                }
            }

            #[test]
            fn rejects_invalid_inputs() {
                let (commitments, openings) = commitments_and_openings();
                assert_eq!(
                    build(&commitments[..3], AMOUNTS, BIT_LENGTHS, openings.as_slice())
                        .unwrap_err(),
                    ProofGenerationError::IllegalCommitmentLength,
                );
                assert_eq!(
                    build(commitments, &AMOUNTS[..3], BIT_LENGTHS, openings.as_slice())
                        .unwrap_err(),
                    ProofGenerationError::IllegalCommitmentLength,
                );
                assert_eq!(
                    build(commitments, AMOUNTS, BIT_LENGTHS, &openings[..3]).unwrap_err(),
                    ProofGenerationError::IllegalCommitmentLength,
                );
                assert_eq!(
                    build(commitments, AMOUNTS, &BIT_LENGTHS[..3], openings.as_slice())
                        .unwrap_err(),
                    ProofGenerationError::IllegalAmountBitLength,
                );
                assert_eq!(
                    build(
                        Vec::<PedersenCommitment>::new(),
                        Vec::<u64>::new(),
                        Vec::<usize>::new(),
                        Vec::<PedersenOpening>::new(),
                    )
                    .unwrap_err(),
                    ProofGenerationError::IllegalAmountBitLength,
                );

                let (commitment, opening) = Pedersen::new(1_u64);
                let mut too_many_bit_lengths = [$total_bits / 9; 9];
                too_many_bit_lengths[8] = $total_bits / 9 + $total_bits % 9;
                assert_eq!(
                    build([commitment; 9], [1; 9], too_many_bit_lengths, [&opening; 9],)
                        .unwrap_err(),
                    ProofGenerationError::IllegalCommitmentLength,
                );

                // Keep the total valid so that rejection depends on the zero component.
                assert!(matches!(
                    build(
                        [commitment; 5],
                        [1; 5],
                        [
                            0,
                            $total_bits / 4,
                            $total_bits / 4,
                            $total_bits / 4,
                            $total_bits / 4
                        ],
                        [&opening; 5],
                    ),
                    Err(ProofGenerationError::RangeProof(_)),
                ));

                let mut identity_commitments = commitments;
                identity_commitments[0] = PedersenCommitment::default();
                assert_eq!(
                    build(
                        identity_commitments,
                        AMOUNTS,
                        BIT_LENGTHS,
                        openings.as_slice()
                    )
                    .unwrap_err(),
                    ProofGenerationError::InvalidCommitment,
                );
            }

            #[test]
            fn rejects_invalid_context_and_padding() {
                let (commitments, openings) = commitments_and_openings();
                let proof = build(commitments, AMOUNTS, BIT_LENGTHS, openings).unwrap();
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
