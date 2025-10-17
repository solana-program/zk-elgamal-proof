//! Plain Old Data types for the Grouped ElGamal encryption scheme.

#[cfg(not(target_os = "solana"))]
use crate::encryption::grouped_elgamal::GroupedElGamalCiphertext;
use {
    crate::errors::ElGamalError,
    solana_zk_sdk_pod::encryption::grouped_elgamal::{
        PodGroupedElGamalCiphertext2Handles, PodGroupedElGamalCiphertext3Handles,
    },
};

#[cfg(not(target_os = "solana"))]
impl From<GroupedElGamalCiphertext<2>> for PodGroupedElGamalCiphertext2Handles {
    fn from(decoded_ciphertext: GroupedElGamalCiphertext<2>) -> Self {
        Self(decoded_ciphertext.to_bytes().try_into().unwrap())
    }
}

#[cfg(not(target_os = "solana"))]
impl TryFrom<PodGroupedElGamalCiphertext2Handles> for GroupedElGamalCiphertext<2> {
    type Error = ElGamalError;

    fn try_from(pod_ciphertext: PodGroupedElGamalCiphertext2Handles) -> Result<Self, Self::Error> {
        Self::from_bytes(&pod_ciphertext.0).ok_or(ElGamalError::CiphertextDeserialization)
    }
}

#[cfg(not(target_os = "solana"))]
impl From<GroupedElGamalCiphertext<3>> for PodGroupedElGamalCiphertext3Handles {
    fn from(decoded_ciphertext: GroupedElGamalCiphertext<3>) -> Self {
        Self(decoded_ciphertext.to_bytes().try_into().unwrap())
    }
}

#[cfg(not(target_os = "solana"))]
impl TryFrom<PodGroupedElGamalCiphertext3Handles> for GroupedElGamalCiphertext<3> {
    type Error = ElGamalError;

    fn try_from(pod_ciphertext: PodGroupedElGamalCiphertext3Handles) -> Result<Self, Self::Error> {
        Self::from_bytes(&pod_ciphertext.0).ok_or(ElGamalError::CiphertextDeserialization)
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::encryption::{
            elgamal::ElGamalKeypair, grouped_elgamal::GroupedElGamal, pedersen::Pedersen,
        },
        solana_zk_sdk_pod::{
            encryption::{elgamal::PodElGamalCiphertext, pedersen::PodPedersenCommitment},
            errors::PodParseError,
        },
    };

    #[test]
    fn test_2_handles_ciphertext_extraction() {
        let elgamal_keypair_0 = ElGamalKeypair::new_rand();
        let elgamal_keypair_1 = ElGamalKeypair::new_rand();

        let amount: u64 = 10;
        let (commitment, opening) = Pedersen::new(amount);

        let grouped_ciphertext = GroupedElGamal::encrypt_with(
            [elgamal_keypair_0.pubkey(), elgamal_keypair_1.pubkey()],
            amount,
            &opening,
        );
        let pod_grouped_ciphertext: PodGroupedElGamalCiphertext2Handles = grouped_ciphertext.into();

        let expected_pod_commitment: PodPedersenCommitment = commitment.into();
        let actual_pod_commitment = pod_grouped_ciphertext.extract_commitment();
        assert_eq!(expected_pod_commitment, actual_pod_commitment);

        let expected_ciphertext_0 = elgamal_keypair_0.pubkey().encrypt_with(amount, &opening);
        let expected_pod_ciphertext_0: PodElGamalCiphertext = expected_ciphertext_0.into();
        let actual_pod_ciphertext_0 = pod_grouped_ciphertext.try_extract_ciphertext(0).unwrap();
        assert_eq!(expected_pod_ciphertext_0, actual_pod_ciphertext_0);

        let expected_ciphertext_1 = elgamal_keypair_1.pubkey().encrypt_with(amount, &opening);
        let expected_pod_ciphertext_1: PodElGamalCiphertext = expected_ciphertext_1.into();
        let actual_pod_ciphertext_1 = pod_grouped_ciphertext.try_extract_ciphertext(1).unwrap();
        assert_eq!(expected_pod_ciphertext_1, actual_pod_ciphertext_1);

        let err = pod_grouped_ciphertext
            .try_extract_ciphertext(2)
            .unwrap_err();
        assert_eq!(err, PodParseError::GroupedCiphertextIndexOutOfBounds);
    }

    #[test]
    fn test_3_handles_ciphertext_extraction() {
        let elgamal_keypair_0 = ElGamalKeypair::new_rand();
        let elgamal_keypair_1 = ElGamalKeypair::new_rand();
        let elgamal_keypair_2 = ElGamalKeypair::new_rand();

        let amount: u64 = 10;
        let (commitment, opening) = Pedersen::new(amount);

        let grouped_ciphertext = GroupedElGamal::encrypt_with(
            [
                elgamal_keypair_0.pubkey(),
                elgamal_keypair_1.pubkey(),
                elgamal_keypair_2.pubkey(),
            ],
            amount,
            &opening,
        );
        let pod_grouped_ciphertext: PodGroupedElGamalCiphertext3Handles = grouped_ciphertext.into();

        let expected_pod_commitment: PodPedersenCommitment = commitment.into();
        let actual_pod_commitment = pod_grouped_ciphertext.extract_commitment();
        assert_eq!(expected_pod_commitment, actual_pod_commitment);

        let expected_ciphertext_0 = elgamal_keypair_0.pubkey().encrypt_with(amount, &opening);
        let expected_pod_ciphertext_0: PodElGamalCiphertext = expected_ciphertext_0.into();
        let actual_pod_ciphertext_0 = pod_grouped_ciphertext.try_extract_ciphertext(0).unwrap();
        assert_eq!(expected_pod_ciphertext_0, actual_pod_ciphertext_0);

        let expected_ciphertext_1 = elgamal_keypair_1.pubkey().encrypt_with(amount, &opening);
        let expected_pod_ciphertext_1: PodElGamalCiphertext = expected_ciphertext_1.into();
        let actual_pod_ciphertext_1 = pod_grouped_ciphertext.try_extract_ciphertext(1).unwrap();
        assert_eq!(expected_pod_ciphertext_1, actual_pod_ciphertext_1);

        let expected_ciphertext_2 = elgamal_keypair_2.pubkey().encrypt_with(amount, &opening);
        let expected_pod_ciphertext_2: PodElGamalCiphertext = expected_ciphertext_2.into();
        let actual_pod_ciphertext_2 = pod_grouped_ciphertext.try_extract_ciphertext(2).unwrap();
        assert_eq!(expected_pod_ciphertext_2, actual_pod_ciphertext_2);

        let err = pod_grouped_ciphertext
            .try_extract_ciphertext(3)
            .unwrap_err();
        assert_eq!(err, PodParseError::GroupedCiphertextIndexOutOfBounds);
    }
}
