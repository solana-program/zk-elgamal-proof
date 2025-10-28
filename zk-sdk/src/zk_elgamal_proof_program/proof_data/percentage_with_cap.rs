//! The percentage-with-cap proof instruction.
//!
//! The percentage-with-cap proof is defined with respect to three Pedersen commitments that
//! encodes values referred to as a `percentage`, `delta`, and `claimed` amounts. The proof
//! certifies that either
//! - the `percentage` amount is equal to a constant (referred to as the `max_value`)
//! - the `delta` and `claimed` amounts are equal

use {
    crate::zk_elgamal_proof_program::proof_data::{ProofType, ZkProofData},
    solana_zk_sdk_pod::proof_data::percentage_with_cap::{
        PercentageWithCapProofContext, PercentageWithCapProofData,
    },
};
#[cfg(not(target_os = "solana"))]
use {
    crate::{
        encryption::pedersen::{PedersenCommitment, PedersenOpening},
        sigma_proofs::percentage_with_cap::PercentageWithCapProof,
        zk_elgamal_proof_program::{
            errors::{ProofGenerationError, ProofVerificationError},
            proof_data::ProofContext,
        },
    },
    bytemuck::bytes_of,
    merlin::Transcript,
    solana_zk_sdk_pod::encryption::pedersen::PodPedersenCommitment,
    std::convert::TryInto,
};

#[cfg(not(target_os = "solana"))]
pub trait PercentageWithCapProofDataExt {
    #[allow(clippy::too_many_arguments)]
    fn new(
        percentage_commitment: &PedersenCommitment,
        percentage_opening: &PedersenOpening,
        percentage_amount: u64,
        delta_commitment: &PedersenCommitment,
        delta_opening: &PedersenOpening,
        delta_amount: u64,
        claimed_commitment: &PedersenCommitment,
        claimed_opening: &PedersenOpening,
        max_value: u64,
    ) -> Result<Self, ProofGenerationError>
    where
        Self: Sized;
}

#[cfg(not(target_os = "solana"))]
impl PercentageWithCapProofDataExt for PercentageWithCapProofData {
    #[allow(clippy::too_many_arguments)]
    fn new(
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

        let mut transcript = context.new_transcript();

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
        let mut transcript = self.context.new_transcript();

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

#[cfg(not(target_os = "solana"))]
impl ProofContext for PercentageWithCapProofContext {
    fn new_transcript(&self) -> Transcript {
        let mut transcript = Transcript::new(b"percentage-with-cap-instruction");
        transcript.append_message(
            b"percentage-commitment",
            bytes_of(&self.percentage_commitment),
        );
        transcript.append_message(b"delta-commitment", bytes_of(&self.delta_commitment));
        transcript.append_message(b"claimed-commitment", bytes_of(&self.claimed_commitment));
        transcript.append_u64(b"max-value", self.max_value.into());
        transcript
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
        let base_amount: u64 = 55;
        let max_value: u64 = 3;

        let percentage_rate: u16 = 555;
        let percentage_amount: u64 = 4;

        let (transfer_commitment, transfer_opening) = Pedersen::new(base_amount);
        let (percentage_commitment, percentage_opening) = Pedersen::new(max_value);

        let scalar_rate = Scalar::from(percentage_rate);
        let delta_commitment =
            &percentage_commitment * &Scalar::from(10000_u64) - &transfer_commitment * &scalar_rate;
        let delta_opening =
            &percentage_opening * &Scalar::from(10000_u64) - &transfer_opening * &scalar_rate;

        let (claimed_commitment, claimed_opening) = Pedersen::new(0_u64);

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
    }
}
