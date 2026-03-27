//! Plain Old Data types for the AES128-GCM-SIV authenticated encryption scheme.

#[cfg(feature = "serde")]
use crate::macros::impl_serde_base64;
use {
    crate::{
        encryption::AE_CIPHERTEXT_LEN,
        macros::{impl_from_bytes, impl_from_str},
    },
    base64::{prelude::BASE64_STANDARD, Engine},
    bytemuck::{Pod, Zeroable},
    core::fmt,
};

/// Maximum length of a base-64 encoded authenticated encryption ciphertext
const AE_CIPHERTEXT_MAX_BASE64_LEN: usize = 48;

/// The `AeCiphertext` type as a `Pod`.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct PodAeCiphertext(pub [u8; AE_CIPHERTEXT_LEN]);

// `PodAeCiphertext` is a wrapper type for a byte array, which is both `Pod` and `Zeroable`. However,
// the marker traits `bytemuck::Pod` and `bytemuck::Zeroable` can only be derived for power-of-two
// length byte arrays. Directly implement these traits for `PodAeCiphertext`.
unsafe impl Zeroable for PodAeCiphertext {}
unsafe impl Pod for PodAeCiphertext {}

impl fmt::Debug for PodAeCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl fmt::Display for PodAeCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.0))
    }
}

impl_from_str!(
    TYPE = PodAeCiphertext,
    BYTES_LEN = AE_CIPHERTEXT_LEN,
    BASE64_LEN = AE_CIPHERTEXT_MAX_BASE64_LEN
);

impl_from_bytes!(TYPE = PodAeCiphertext, BYTES_LEN = AE_CIPHERTEXT_LEN);

#[cfg(feature = "serde")]
impl_serde_base64!(TYPE = PodAeCiphertext);

impl Default for PodAeCiphertext {
    fn default() -> Self {
        Self::zeroed()
    }
}

#[cfg(test)]
mod tests {
    use {super::*, solana_zk_sdk::encryption::auth_encryption::AeKey, std::str::FromStr};

    #[test]
    fn ae_ciphertext_fromstr() {
        let ae_key = AeKey::new_rand();
        let expected_ae_ciphertext = PodAeCiphertext(ae_key.encrypt(0_u64).to_bytes());

        let ae_ciphertext_base64_str = format!("{}", expected_ae_ciphertext);
        let computed_ae_ciphertext = PodAeCiphertext::from_str(&ae_ciphertext_base64_str).unwrap();

        assert_eq!(expected_ae_ciphertext, computed_ae_ciphertext);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_ae_ciphertext_serde() {
        let ae_key = AeKey::new_rand();
        let expected_ae_ciphertext = PodAeCiphertext(ae_key.encrypt(0_u64).to_bytes());

        let serialized = serde_json::to_string(&expected_ae_ciphertext).unwrap();
        assert_eq!(serialized, format!("\"{}\"", expected_ae_ciphertext));

        let deserialized: PodAeCiphertext = serde_json::from_str(&serialized).unwrap();
        assert_eq!(expected_ae_ciphertext, deserialized);
    }
}
