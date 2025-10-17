//! Plain Old Data type for the Pedersen commitment scheme.

use solana_zk_sdk_pod::encryption::pedersen::PodPedersenCommitment;
#[cfg(not(target_os = "solana"))]
use {
    crate::{encryption::pedersen::PedersenCommitment, errors::ElGamalError},
    // curve25519_dalek::ristretto::CompressedRistretto,
};

#[cfg(not(target_os = "solana"))]
impl From<PedersenCommitment> for PodPedersenCommitment {
    fn from(decoded_commitment: PedersenCommitment) -> Self {
        Self(decoded_commitment.to_bytes())
    }
}

// // For proof verification, interpret pod::PedersenCommitment directly as CompressedRistretto
// #[cfg(not(target_os = "solana"))]
// impl From<PodPedersenCommitment> for CompressedRistretto {
//     fn from(pod_commitment: PodPedersenCommitment) -> Self {
//         Self(pod_commitment.0)
//     }
// }

#[cfg(not(target_os = "solana"))]
impl TryFrom<PodPedersenCommitment> for PedersenCommitment {
    type Error = ElGamalError;

    fn try_from(pod_commitment: PodPedersenCommitment) -> Result<Self, Self::Error> {
        Self::from_bytes(&pod_commitment.0).ok_or(ElGamalError::CiphertextDeserialization)
    }
}
