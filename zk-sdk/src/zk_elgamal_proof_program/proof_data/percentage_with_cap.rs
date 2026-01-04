//! The percentage-with-cap proof instruction.
//!
//! The percentage-with-cap proof is defined with respect to three Pedersen commitments that
//! encodes values referred to as a `percentage`, `delta`, and `claimed` amounts. The proof
//! certifies that either
//! - the `percentage` amount is equal to a constant (referred to as the `max_value`)
//! - the `delta` and `claimed` amounts are equal

#[cfg(not(target_os = "solana"))]
use {
    crate::{
        encryption::pedersen::{Pedersen, PedersenCommitment, PedersenOpening},
        sigma_proofs::percentage_with_cap::PercentageWithCapProof,
        transcript::TranscriptProtocol,
        zk_elgamal_proof_program::errors::{ProofGenerationError, ProofVerificationError},
    },
    merlin::Transcript,
    std::convert::TryInto,
};
use {
    crate::{
        encryption::pod::pedersen::PodPedersenCommitment,
        pod::PodU64,
        sigma_proofs::pod::PodPercentageWithCapProof,
        zk_elgamal_proof_program::proof_data::{ProofType, ZkProofData},
    },
    bytemuck_derive::{Pod, Zeroable},
};

/// The instruction data that is needed for the `ProofInstruction::VerifyPercentageWithCap`
/// instruction.
///
/// It includes the cryptographic proof as well as the context data information needed to verify
/// the proof.
#[derive(Clone, Copy, Pod, Zeroable, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct PercentageWithCapProofData {
    pub context: PercentageWithCapProofContext,

    pub proof: PodPercentageWithCapProof,
}

/// The context data needed to verify a percentage-with-cap proof.
///
/// We refer to [`ZK ElGamal proof`] for the formal details on how the percentage-with-cap proof is
/// computed.
///
/// [`ZK ElGamal proof`]: https://docs.solanalabs.com/runtime/zk-token-proof
#[derive(Clone, Copy, Pod, Zeroable, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct PercentageWithCapProofContext {
    /// The Pedersen commitment to the percentage amount.
    pub percentage_commitment: PodPedersenCommitment,

    /// The Pedersen commitment to the delta amount.
    pub delta_commitment: PodPedersenCommitment,

    /// The Pedersen commitment to the claimed amount.
    pub claimed_commitment: PodPedersenCommitment,

    /// The maximum cap bound.
    pub max_value: PodU64,
}

#[cfg(not(target_os = "solana"))]
impl PercentageWithCapProofData {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        percentage_commitment: &PedersenCommitment,
        percentage_opening: &PedersenOpening,
        percentage_amount: u64,
        delta_commitment: &PedersenCommitment,
        delta_opening: &PedersenOpening,
        delta_amount: u64,
        claimed_commitment: &PedersenCommitment,
        claimed_opening: &PedersenOpening,
        max_value: u64,
    ) -> Result<Self, ProofGenerationError> {
        // Verify percentage commitment
        if *percentage_commitment != Pedersen::with(percentage_amount, percentage_opening) {
            return Err(ProofGenerationError::InconsistentInput);
        }
        // Verify delta commitment
        if *delta_commitment != Pedersen::with(delta_amount, delta_opening) {
            return Err(ProofGenerationError::InconsistentInput);
        }
        // Verify claimed commitment
        if *claimed_commitment != Pedersen::with(delta_amount, claimed_opening) {
            return Err(ProofGenerationError::InconsistentInput);
        }

        let pod_percentage_commitment = PodPedersenCommitment(percentage_commitment.to_bytes());
        let pod_delta_commitment = PodPedersenCommitment(delta_commitment.to_bytes());
        let pod_claimed_commitment = PodPedersenCommitment(claimed_commitment.to_bytes());
        let pod_max_value = max_value.into();

        let context = PercentageWithCapProofContext {
            percentage_commitment: pod_percentage_commitment,
            delta_commitment: pod_delta_commitment,
            claimed_commitment: pod_claimed_commitment,
            max_value: pod_max_value,
        };

        let mut transcript =
            Transcript::new_zk_elgamal_transcript(b"percentage-with-cap-instruction");

        let proof = PercentageWithCapProof::new(
            percentage_commitment,
            percentage_opening,
            percentage_amount,
            delta_commitment,
            delta_opening,
            delta_amount,
            claimed_commitment,
            claimed_opening,
            max_value,
            &mut transcript,
        )
        .into();

        Ok(Self { context, proof })
    }
}

impl ZkProofData<PercentageWithCapProofContext> for PercentageWithCapProofData {
    const PROOF_TYPE: ProofType = ProofType::PercentageWithCap;

    fn context_data(&self) -> &PercentageWithCapProofContext {
        &self.context
    }

    #[cfg(not(target_os = "solana"))]
    fn verify_proof(&self) -> Result<(), ProofVerificationError> {
        let mut transcript =
            Transcript::new_zk_elgamal_transcript(b"percentage-with-cap-instruction");

        let percentage_commitment = self.context.percentage_commitment.try_into()?;
        let delta_commitment = self.context.delta_commitment.try_into()?;
        let claimed_commitment = self.context.claimed_commitment.try_into()?;
        let max_value = self.context.max_value.into();
        let proof: PercentageWithCapProof = self.proof.try_into()?;

        proof
            .verify(
                &percentage_commitment,
                &delta_commitment,
                &claimed_commitment,
                max_value,
                &mut transcript,
            )
            .map_err(|e| e.into())
    }
}

#[cfg(test)]
mod test {
    use {super::*, crate::encryption::pedersen::Pedersen, curve25519_dalek::scalar::Scalar};

    #[test]
    fn test_percentage_with_cap_instruction_correctness() {
        // base amount is below max value
        let base_amount: u64 = 1;
        let max_value: u64 = 3;

        let percentage_rate: u16 = 400;
        let percentage_amount: u64 = 1;
        let delta_amount: u64 = 9600;

        let (base_commitment, base_opening) = Pedersen::new(base_amount);
        let (percentage_commitment, percentage_opening) = Pedersen::new(percentage_amount);

        let scalar_rate = Scalar::from(percentage_rate);
        let delta_commitment =
            &percentage_commitment * Scalar::from(10_000_u64) - &base_commitment * &scalar_rate;
        let delta_opening =
            &percentage_opening * &Scalar::from(10_000_u64) - &base_opening * &scalar_rate;

        let (claimed_commitment, claimed_opening) = Pedersen::new(delta_amount);

        let proof_data = PercentageWithCapProofData::new(
            &percentage_commitment,
            &percentage_opening,
            percentage_amount,
            &delta_commitment,
            &delta_opening,
            delta_amount,
            &claimed_commitment,
            &claimed_opening,
            max_value,
        )
        .unwrap();

        assert!(proof_data.verify_proof().is_ok());

        // base amount is equal to max value
        let max_value: u64 = 3;
        let percentage_amount: u64 = 3;
        let (percentage_commitment, percentage_opening) = Pedersen::new(percentage_amount);
        let delta_amount: u64 = 100;
        let (delta_commitment, delta_opening) = Pedersen::new(delta_amount);
        let (claimed_commitment, claimed_opening) = Pedersen::new(delta_amount);

        let proof_data = PercentageWithCapProofData::new(
            &percentage_commitment,
            &percentage_opening,
            percentage_amount,
            &delta_commitment,
            &delta_opening,
            delta_amount,
            &claimed_commitment,
            &claimed_opening,
            max_value,
        )
        .unwrap();

        assert!(proof_data.verify_proof().is_ok());

        let (fake_commitment, _) = Pedersen::new(999_u64);

        let result = PercentageWithCapProofData::new(
            &percentage_commitment,
            &percentage_opening,
            percentage_amount,
            &delta_commitment,
            &delta_opening,
            delta_amount,
            &fake_commitment,
            &claimed_opening,
            max_value,
        );

        assert_eq!(result, Err(ProofGenerationError::InconsistentInput));
    }
}
