//! Plain Old Data types for the Grouped ElGamal encryption scheme.

use {
    crate::{
        encryption::{
            elgamal::PodElGamalCiphertext, pedersen::PodPedersenCommitment, DECRYPT_HANDLE_LEN,
            ELGAMAL_CIPHERTEXT_LEN, PEDERSEN_COMMITMENT_LEN,
        },
        macros::{impl_from_bytes, impl_from_str},
    },
    base64::{prelude::BASE64_STANDARD, Engine},
    bytemuck::Zeroable,
    std::fmt,
};

/// Maximum length of a base64 encoded grouped ElGamal ciphertext with 2 handles
const GROUPED_ELGAMAL_CIPHERTEXT_2_HANDLES_MAX_BASE64_LEN: usize = 132;

/// Maximum length of a base64 encoded grouped ElGamal ciphertext with 3 handles
const GROUPED_ELGAMAL_CIPHERTEXT_3_HANDLES_MAX_BASE64_LEN: usize = 176;

macro_rules! impl_extract {
    (TYPE = $type:ident) => {
        impl $type {
            /// Extract the commitment component from a grouped ciphertext
            pub fn extract_commitment(&self) -> PodPedersenCommitment {
                // `GROUPED_ELGAMAL_CIPHERTEXT_2_HANDLES` guaranteed to be at least `PEDERSEN_COMMITMENT_LEN`
                let commitment = self.0[..PEDERSEN_COMMITMENT_LEN].try_into().unwrap();
                PodPedersenCommitment(commitment)
            }

            /// Extract a regular ElGamal ciphertext using the decrypt handle at a specified index.
            pub fn try_extract_ciphertext(
                &self,
                index: usize,
            ) -> Result<PodElGamalCiphertext, crate::errors::PodParseError> {
                let mut ciphertext_bytes = [0u8; ELGAMAL_CIPHERTEXT_LEN];
                ciphertext_bytes[..PEDERSEN_COMMITMENT_LEN]
                    .copy_from_slice(&self.0[..PEDERSEN_COMMITMENT_LEN]);

                let handle_start = DECRYPT_HANDLE_LEN
                    .checked_mul(index)
                    .and_then(|n| n.checked_add(PEDERSEN_COMMITMENT_LEN))
                    .ok_or(crate::errors::PodParseError::GroupedCiphertextIndexOutOfBounds)?;
                let handle_end = handle_start
                    .checked_add(DECRYPT_HANDLE_LEN)
                    .ok_or(crate::errors::PodParseError::GroupedCiphertextIndexOutOfBounds)?;
                ciphertext_bytes[PEDERSEN_COMMITMENT_LEN..].copy_from_slice(
                    self.0
                        .get(handle_start..handle_end)
                        .ok_or(crate::errors::PodParseError::GroupedCiphertextIndexOutOfBounds)?,
                );

                Ok(PodElGamalCiphertext(ciphertext_bytes))
            }
        }
    };
}

/// Byte length of a grouped ElGamal ciphertext with 2 handles
const GROUPED_ELGAMAL_CIPHERTEXT_2_HANDLES: usize =
    PEDERSEN_COMMITMENT_LEN + DECRYPT_HANDLE_LEN + DECRYPT_HANDLE_LEN;

/// Byte length of a grouped ElGamal ciphertext with 3 handles
const GROUPED_ELGAMAL_CIPHERTEXT_3_HANDLES: usize =
    PEDERSEN_COMMITMENT_LEN + DECRYPT_HANDLE_LEN + DECRYPT_HANDLE_LEN + DECRYPT_HANDLE_LEN;

/// The `GroupedElGamalCiphertext` type with two decryption handles as a `Pod`
#[derive(Clone, Copy, bytemuck_derive::Pod, bytemuck_derive::Zeroable, PartialEq, Eq)]
#[repr(transparent)]
pub struct PodGroupedElGamalCiphertext2Handles(pub [u8; GROUPED_ELGAMAL_CIPHERTEXT_2_HANDLES]);

impl fmt::Debug for PodGroupedElGamalCiphertext2Handles {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl Default for PodGroupedElGamalCiphertext2Handles {
    fn default() -> Self {
        Self::zeroed()
    }
}

impl fmt::Display for PodGroupedElGamalCiphertext2Handles {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.0))
    }
}

impl_from_str!(
    TYPE = PodGroupedElGamalCiphertext2Handles,
    BYTES_LEN = GROUPED_ELGAMAL_CIPHERTEXT_2_HANDLES,
    BASE64_LEN = GROUPED_ELGAMAL_CIPHERTEXT_2_HANDLES_MAX_BASE64_LEN
);

impl_from_bytes!(
    TYPE = PodGroupedElGamalCiphertext2Handles,
    BYTES_LEN = GROUPED_ELGAMAL_CIPHERTEXT_2_HANDLES
);

impl_extract!(TYPE = PodGroupedElGamalCiphertext2Handles);

/// The `GroupedElGamalCiphertext` type with three decryption handles as a `Pod`
#[derive(Clone, Copy, bytemuck_derive::Pod, bytemuck_derive::Zeroable, PartialEq, Eq)]
#[repr(transparent)]
pub struct PodGroupedElGamalCiphertext3Handles(pub [u8; GROUPED_ELGAMAL_CIPHERTEXT_3_HANDLES]);

impl fmt::Debug for PodGroupedElGamalCiphertext3Handles {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl Default for PodGroupedElGamalCiphertext3Handles {
    fn default() -> Self {
        Self::zeroed()
    }
}

impl fmt::Display for PodGroupedElGamalCiphertext3Handles {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.0))
    }
}

impl_from_str!(
    TYPE = PodGroupedElGamalCiphertext3Handles,
    BYTES_LEN = GROUPED_ELGAMAL_CIPHERTEXT_3_HANDLES,
    BASE64_LEN = GROUPED_ELGAMAL_CIPHERTEXT_3_HANDLES_MAX_BASE64_LEN
);

impl_from_bytes!(
    TYPE = PodGroupedElGamalCiphertext3Handles,
    BYTES_LEN = GROUPED_ELGAMAL_CIPHERTEXT_3_HANDLES
);

impl_extract!(TYPE = PodGroupedElGamalCiphertext3Handles);
