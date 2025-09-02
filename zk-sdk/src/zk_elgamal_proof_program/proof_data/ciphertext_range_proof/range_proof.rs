//! The 256-bit batched range proof instruction.

#[cfg(not(target_os = "solana"))]
use {
    crate::{
        encryption::pedersen::{PedersenCommitment, PedersenOpening},
        range_proof::RangeProof,
        zk_elgamal_proof_program::{
            errors::{ProofGenerationError, ProofVerificationError},
           
        },
    },
    std::convert::TryInto,
};
use {
    crate::{
        range_proof::pod::PodRangeProofU256,
        zk_elgamal_proof_program::proof_data::{
            ciphertext_range_proof::CiphertextRangeProofContext , ProofType, ZkProofData,
        },
    },
    bytemuck_derive::{Pod, Zeroable},
};


/// The maximum number of Pedersen commitments that can be processed in a single batched range proof.
const MAX_COMMITMENTS: usize = 8;

/// A bit length in a batched range proof must be at most 128.
///
/// A 256-bit range proof on a single Pedersen commitment is meaningless and hence enforce an upper
/// bound as the largest power-of-two number less than 256.
#[cfg(not(target_os = "solana"))]
const MAX_SINGLE_BIT_LENGTH: usize = 128;


#[cfg(not(target_os = "solana"))]
const BATCHED_RANGE_PROOF_U256_BIT_LENGTH: usize = 256;

/// The instruction data that is needed for the
/// `ProofInstruction::BatchedRangeProofU256Data` instruction.
///
/// It includes the cryptographic proof as well as the context data information needed to verify
/// the proof.
#[derive(Clone, Copy, Pod, Zeroable)]
#[repr(C)]
pub struct BatchedRangeProofU256Data {
    /// The context data for a batched range proof
    pub context: CiphertextRangeProofContext ,

    /// The batched range proof
    pub proof: PodRangeProofU256,
}

#[cfg(not(target_os = "solana"))]
impl BatchedRangeProofU256Data {
    pub fn new(
        commitments: Vec<&PedersenCommitment>,
        amounts: Vec<u64>,
        bit_lengths: Vec<usize>,
        openings: Vec<&PedersenOpening>,
        ciphertext: &[u8;32]
       
        
    ) -> Result<Self, ProofGenerationError> {
        // Range proof on 256 bit length could potentially result in an unexpected behavior and
        // therefore, restrict the bit length to be at most 128. This check is not needed for the
        // `BatchedRangeProofU64` or `BatchedRangeProofU128`.
        if bit_lengths
            .iter()
            .any(|length| *length > MAX_SINGLE_BIT_LENGTH)
        {
            return Err(ProofGenerationError::IllegalCommitmentLength);
        }

        // the sum of the bit lengths must be 256
        let batched_bit_length = bit_lengths
            .iter()
            .try_fold(0_usize, |acc, &x| acc.checked_add(x))
            .ok_or(ProofGenerationError::IllegalAmountBitLength)?;
        if batched_bit_length != BATCHED_RANGE_PROOF_U256_BIT_LENGTH {
            return Err(ProofGenerationError::IllegalAmountBitLength);
        }

        let context =
            CiphertextRangeProofContext ::new(&commitments, &amounts, &bit_lengths, &openings, &ciphertext)?;

        let mut transcript = context.new_transcript();
        let proof = RangeProof::new(amounts, bit_lengths, openings, &mut transcript)?
            .try_into()
            .map_err(|_| ProofGenerationError::ProofLength)?;

        Ok(Self { context, proof })
    }
}

impl ZkProofData<CiphertextRangeProofContext > for BatchedRangeProofU256Data {
    const PROOF_TYPE: ProofType = ProofType::BatchedRangeProofU256;

    fn context_data(&self) -> &CiphertextRangeProofContext {
        &self.context
    }

    #[cfg(not(target_os = "solana"))]
    fn verify_proof(&self , onchain_ciphertext_hash: &[u8;32]) -> Result<(), ProofVerificationError> {
        let (commitments, bit_lengths, ciphertext_hash) = self.context.try_into()?;
        let num_commitments = commitments.len();
    // checks the context ciphertext is same as given on-chain 
        if &ciphertext_hash != onchain_ciphertext_hash {
        return Err(ProofVerificationError::CiphertextMismatch);
    }
        // This check is unique to the 256-bit proof. For 64-bit and 128-bit proofs,
        // the total sum constraint already guarantees that no single bit length can
        // exceed 128. However, for a 256-bit proof, bit lengths can sum to 256
        // while containing a value greater than 128 (e.g., [160, 96]), so this
        // must be explicitly checked.
        if bit_lengths
            .iter()
            .any(|length| *length > MAX_SINGLE_BIT_LENGTH)
        {
            return Err(ProofVerificationError::IllegalCommitmentLength);
        }

        if num_commitments > MAX_COMMITMENTS || num_commitments != bit_lengths.len() {
            return Err(ProofVerificationError::IllegalCommitmentLength);
        }

    
        let mut transcript = self.context_data().new_transcript();
        let proof: RangeProof = self.proof.try_into()?;

        proof
            .verify(commitments.iter().collect(), bit_lengths, &mut transcript)
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
    use sha3::{Sha3_256, Digest};

    #[test]
    fn test_batched_range_proof_256_instruction_correctness() {
        let amount_1 = 100_u64;
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

        // // Create dummy ciphertext data for testing
        let ciphertext = [1u8; 32]; // 64 bytes of dummy ciphertext data
        let mut hasher = Sha3_256::new();
        hasher.update(ciphertext);
        let ciphertext_hash: [u8; 32] = hasher.finalize().into();


        let proof_data = BatchedRangeProofU256Data::new(
            vec![
                &commitment_1,
                &commitment_2,
                &commitment_3,
                &commitment_4,
                &commitment_5,
                &commitment_6,
                &commitment_7,
                &commitment_8,
            ],
            vec![
                amount_1, amount_2, amount_3, amount_4, amount_5, amount_6, amount_7, amount_8,
            ],
            vec![32, 32, 32, 32, 32, 32, 32, 32],
            vec![
                &opening_1, &opening_2, &opening_3, &opening_4, &opening_5, &opening_6, &opening_7,
                &opening_8,
            ],
            &ciphertext, // Added missing ciphertext parameter
        )
        .unwrap();

        assert!(proof_data.verify_proof(&ciphertext_hash).is_ok()); // Added ciphertext parameter

        let amount_1 = 4294967296_u64; // not representable as a 32-bit number
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

        let proof_data = BatchedRangeProofU256Data::new(
            vec![
                &commitment_1,
                &commitment_2,
                &commitment_3,
                &commitment_4,
                &commitment_5,
                &commitment_6,
                &commitment_7,
                &commitment_8,
            ],
            vec![
                amount_1, amount_2, amount_3, amount_4, amount_5, amount_6, amount_7, amount_8,
            ],
            vec![32, 32, 32, 32, 32, 32, 32, 32],
            vec![
                &opening_1, &opening_2, &opening_3, &opening_4, &opening_5, &opening_6, &opening_7,
                &opening_8,
            ],
            &ciphertext, // Added missing ciphertext parameter
        )
        .unwrap();

        assert_eq!(
            proof_data.verify_proof(&ciphertext_hash).unwrap_err(), // Added ciphertext parameter
            ProofVerificationError::RangeProof(RangeProofVerificationError::AlgebraicRelation),
        );
    }
}