//! The twisted ElGamal group encryption implementation.
//!
//! The message space consists of any number that is representable as a scalar (a.k.a. "exponent")
//! for Curve25519.
//!
//! A regular twisted ElGamal ciphertext consists of two components:
//! - A Pedersen commitment that encodes a message to be encrypted
//! - A "decryption handle" that binds the Pedersen opening to a specific public key
//!
//! The ciphertext can be generalized to hold not a single decryption handle, but multiple handles
//! pertaining to multiple ElGamal public keys. These ciphertexts are referred to as a "grouped"
//! ElGamal ciphertext.
//!

use {
    crate::{
        encryption::{
            discrete_log::DiscreteLog,
            elgamal::{DecryptHandle, ElGamalCiphertext, ElGamalPubkey, ElGamalSecretKey},
            pedersen::{Pedersen, PedersenCommitment, PedersenOpening},
        },
        errors::ElGamalError,
        RISTRETTO_POINT_LEN,
    },
    curve25519_dalek::scalar::Scalar,
    solana_zk_sdk_pod::encryption::grouped_elgamal::{
        PodGroupedElGamalCiphertext2Handles, PodGroupedElGamalCiphertext3Handles,
    },
    thiserror::Error,
};

#[derive(Error, Clone, Debug, Eq, PartialEq)]
pub enum GroupedElGamalError {
    #[error("index out of bounds")]
    IndexOutOfBounds,
}

/// Algorithm handle for the grouped ElGamal encryption
pub struct GroupedElGamal<const N: usize>;
impl<const N: usize> GroupedElGamal<N> {
    /// Encrypts an amount under an array of ElGamal public keys.
    ///
    /// This function is randomized. It internally samples a scalar element using `OsRng`.
    pub fn encrypt<T: Into<Scalar>>(
        pubkeys: [&ElGamalPubkey; N],
        amount: T,
    ) -> GroupedElGamalCiphertext<N> {
        let (commitment, opening) = Pedersen::new(amount);
        let handles: [DecryptHandle; N] = pubkeys
            .iter()
            .map(|handle| handle.decrypt_handle(&opening))
            .collect::<Vec<DecryptHandle>>()
            .try_into()
            .unwrap();

        GroupedElGamalCiphertext {
            commitment,
            handles,
        }
    }

    /// Encrypts an amount under an array of ElGamal public keys using a specified Pedersen
    /// opening.
    pub fn encrypt_with<T: Into<Scalar>>(
        pubkeys: [&ElGamalPubkey; N],
        amount: T,
        opening: &PedersenOpening,
    ) -> GroupedElGamalCiphertext<N> {
        let commitment = Pedersen::with(amount, opening);
        let handles: [DecryptHandle; N] = pubkeys
            .iter()
            .map(|handle| handle.decrypt_handle(opening))
            .collect::<Vec<DecryptHandle>>()
            .try_into()
            .unwrap();

        GroupedElGamalCiphertext {
            commitment,
            handles,
        }
    }

    /// Converts a grouped ElGamal ciphertext into a regular ElGamal ciphertext using the decrypt
    /// handle at a specified index.
    fn to_elgamal_ciphertext(
        grouped_ciphertext: &GroupedElGamalCiphertext<N>,
        index: usize,
    ) -> Result<ElGamalCiphertext, GroupedElGamalError> {
        let handle = grouped_ciphertext
            .handles
            .get(index)
            .ok_or(GroupedElGamalError::IndexOutOfBounds)?;

        Ok(ElGamalCiphertext {
            commitment: grouped_ciphertext.commitment,
            handle: *handle,
        })
    }
}

impl<const N: usize> GroupedElGamal<N> {
    /// Decrypts a grouped ElGamal ciphertext using an ElGamal secret key pertaining to a
    /// decryption handle at a specified index.
    ///
    /// The output of this function is of type `DiscreteLog`. To recover the originally encrypted
    /// amount, use `DiscreteLog::decode`.
    fn decrypt(
        grouped_ciphertext: &GroupedElGamalCiphertext<N>,
        secret: &ElGamalSecretKey,
        index: usize,
    ) -> Result<DiscreteLog, GroupedElGamalError> {
        Self::to_elgamal_ciphertext(grouped_ciphertext, index)
            .map(|ciphertext| ciphertext.decrypt(secret))
    }

    /// Decrypts a grouped ElGamal ciphertext to a number that is interpreted as a positive 32-bit
    /// number (but still of type `u64`).
    ///
    /// If the originally encrypted amount is not a positive 32-bit number, then the function
    /// Result contains `None`.
    ///
    /// NOTE: This function is not constant time.
    fn decrypt_u32(
        grouped_ciphertext: &GroupedElGamalCiphertext<N>,
        secret: &ElGamalSecretKey,
        index: usize,
    ) -> Result<Option<u64>, GroupedElGamalError> {
        Self::to_elgamal_ciphertext(grouped_ciphertext, index)
            .map(|ciphertext| ciphertext.decrypt_u32(secret))
    }
}

/// A grouped ElGamal ciphertext.
///
/// The type is defined with a generic constant parameter that specifies the number of
/// decryption handles that the ciphertext holds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GroupedElGamalCiphertext<const N: usize> {
    pub commitment: PedersenCommitment,
    pub handles: [DecryptHandle; N],
}

impl<const N: usize> GroupedElGamalCiphertext<N> {
    /// Converts a grouped ElGamal ciphertext into a regular ElGamal ciphertext using the decrypt
    /// handle at a specified index.
    pub fn to_elgamal_ciphertext(
        &self,
        index: usize,
    ) -> Result<ElGamalCiphertext, GroupedElGamalError> {
        GroupedElGamal::to_elgamal_ciphertext(self, index)
    }

    /// The expected length of a serialized grouped ElGamal ciphertext.
    ///
    /// A grouped ElGamal ciphertext consists of a Pedersen commitment and an array of decryption
    /// handles. The commitment and decryption handles are each a single Curve25519 group element
    /// that is serialized as 32 bytes. Therefore, the total byte length of a grouped ciphertext is
    /// `(N+1) * 32`.
    fn expected_byte_length() -> usize {
        N.checked_add(1)
            .and_then(|length| length.checked_mul(RISTRETTO_POINT_LEN))
            .unwrap()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::expected_byte_length());
        buf.extend_from_slice(&self.commitment.to_bytes());
        self.handles
            .iter()
            .for_each(|handle| buf.extend_from_slice(&handle.to_bytes()));
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != Self::expected_byte_length() {
            return None;
        }

        let mut iter = bytes.chunks(RISTRETTO_POINT_LEN);
        let commitment = PedersenCommitment::from_bytes(iter.next()?)?;

        let mut handles = Vec::with_capacity(N);
        for handle_bytes in iter {
            handles.push(DecryptHandle::from_bytes(handle_bytes)?);
        }

        Some(Self {
            commitment,
            handles: handles.try_into().unwrap(),
        })
    }
}

impl<const N: usize> GroupedElGamalCiphertext<N> {
    /// Decrypts the grouped ElGamal ciphertext using an ElGamal secret key pertaining to a
    /// specified index.
    ///
    /// The output of this function is of type `DiscreteLog`. To recover the originally encrypted
    /// amount, use `DiscreteLog::decode`.
    pub fn decrypt(
        &self,
        secret: &ElGamalSecretKey,
        index: usize,
    ) -> Result<DiscreteLog, GroupedElGamalError> {
        GroupedElGamal::decrypt(self, secret, index)
    }

    /// Decrypts the grouped ElGamal ciphertext to a number that is interpreted as a positive 32-bit
    /// number (but still of type `u64`).
    ///
    /// If the originally encrypted amount is not a positive 32-bit number, then the function
    /// returns `None`.
    ///
    /// NOTE: This function is not constant time.
    pub fn decrypt_u32(
        &self,
        secret: &ElGamalSecretKey,
        index: usize,
    ) -> Result<Option<u64>, GroupedElGamalError> {
        GroupedElGamal::decrypt_u32(self, secret, index)
    }
}

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
        crate::encryption::elgamal::ElGamalKeypair,
        solana_zk_sdk_pod::{
            encryption::{elgamal::PodElGamalCiphertext, pedersen::PodPedersenCommitment},
            errors::PodParseError,
        },
    };

    #[test]
    fn test_grouped_elgamal_encrypt_decrypt_correctness() {
        let elgamal_keypair_0 = ElGamalKeypair::new_rand();
        let elgamal_keypair_1 = ElGamalKeypair::new_rand();
        let elgamal_keypair_2 = ElGamalKeypair::new_rand();

        let amount: u64 = 10;
        let grouped_ciphertext = GroupedElGamal::encrypt(
            [
                elgamal_keypair_0.pubkey(),
                elgamal_keypair_1.pubkey(),
                elgamal_keypair_2.pubkey(),
            ],
            amount,
        );

        assert_eq!(
            Some(amount),
            grouped_ciphertext
                .decrypt_u32(elgamal_keypair_0.secret(), 0)
                .unwrap()
        );

        assert_eq!(
            Some(amount),
            grouped_ciphertext
                .decrypt_u32(elgamal_keypair_1.secret(), 1)
                .unwrap()
        );

        assert_eq!(
            Some(amount),
            grouped_ciphertext
                .decrypt_u32(elgamal_keypair_2.secret(), 2)
                .unwrap()
        );

        assert_eq!(
            GroupedElGamalError::IndexOutOfBounds,
            grouped_ciphertext
                .decrypt_u32(elgamal_keypair_0.secret(), 3)
                .unwrap_err()
        );
    }

    #[test]
    fn test_grouped_ciphertext_bytes() {
        let elgamal_keypair_0 = ElGamalKeypair::new_rand();
        let elgamal_keypair_1 = ElGamalKeypair::new_rand();
        let elgamal_keypair_2 = ElGamalKeypair::new_rand();

        let amount: u64 = 10;
        let grouped_ciphertext = GroupedElGamal::encrypt(
            [
                elgamal_keypair_0.pubkey(),
                elgamal_keypair_1.pubkey(),
                elgamal_keypair_2.pubkey(),
            ],
            amount,
        );

        let produced_bytes = grouped_ciphertext.to_bytes();
        assert_eq!(produced_bytes.len(), 128);

        let decoded_grouped_ciphertext =
            GroupedElGamalCiphertext::<3>::from_bytes(&produced_bytes).unwrap();
        assert_eq!(
            Some(amount),
            decoded_grouped_ciphertext
                .decrypt_u32(elgamal_keypair_0.secret(), 0)
                .unwrap()
        );

        assert_eq!(
            Some(amount),
            decoded_grouped_ciphertext
                .decrypt_u32(elgamal_keypair_1.secret(), 1)
                .unwrap()
        );

        assert_eq!(
            Some(amount),
            decoded_grouped_ciphertext
                .decrypt_u32(elgamal_keypair_2.secret(), 2)
                .unwrap()
        );
    }

    #[test]
    fn test_decrypt_with_wrong_key_at_valid_index() {
        let keypair_0 = ElGamalKeypair::new_rand();
        let keypair_1 = ElGamalKeypair::new_rand();
        let amount: u64 = 50;

        let grouped_ciphertext =
            GroupedElGamal::encrypt([keypair_0.pubkey(), keypair_1.pubkey()], amount);

        // Attempt to decrypt handle 1 with secret key 0. This must fail.
        let result = grouped_ciphertext
            .decrypt_u32(keypair_0.secret(), 1)
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_zero_sized_group() {
        let amount: u64 = 42;
        let grouped_ciphertext = GroupedElGamal::<0>::encrypt([], amount);

        // Check byte serialization
        let bytes = grouped_ciphertext.to_bytes();
        assert_eq!(bytes.len(), 32); // Only the commitment

        // Check roundtrip
        let decoded_ciphertext = GroupedElGamalCiphertext::<0>::from_bytes(&bytes).unwrap();
        assert_eq!(grouped_ciphertext, decoded_ciphertext);

        // Decryption should fail as there are no handles
        let keypair = ElGamalKeypair::new_rand();
        assert_eq!(
            grouped_ciphertext
                .decrypt_u32(keypair.secret(), 0)
                .unwrap_err(),
            GroupedElGamalError::IndexOutOfBounds
        );
    }

    #[test]
    fn test_malformed_bytes_deserialization() {
        let amount: u64 = 42;

        // Case 1: Bytes too short
        let short_bytes = vec![0; 63]; // Expected 64 for N=1
        assert!(GroupedElGamalCiphertext::<1>::from_bytes(&short_bytes).is_none());

        // Case 2: Bytes too long
        let long_bytes = vec![0; 65]; // Expected 64 for N=1
        assert!(GroupedElGamalCiphertext::<1>::from_bytes(&long_bytes).is_none());

        // Case 3: Correct length, but invalid point data for the commitment
        let mut malformed_commitment = vec![0; 64];
        // This is the compressed form of an invalid point (order 4)
        malformed_commitment[0] = 1;
        assert!(GroupedElGamalCiphertext::<1>::from_bytes(&malformed_commitment).is_none());

        // Case 4: Correct length, but invalid point data for a handle
        let keypair = ElGamalKeypair::new_rand();
        let ciphertext = GroupedElGamal::<1>::encrypt([keypair.pubkey()], amount);
        let mut bytes = ciphertext.to_bytes();
        // Invalidate the handle part
        bytes[32] = 1;
        assert!(GroupedElGamalCiphertext::<1>::from_bytes(&bytes).is_none());
    }

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
