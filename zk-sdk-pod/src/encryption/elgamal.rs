//! Plain Old Data types for the ElGamal encryption scheme.

#[cfg(feature = "serde")]
use crate::macros::impl_serde_base64;
use {
    crate::{
        encryption::{DECRYPT_HANDLE_LEN, ELGAMAL_CIPHERTEXT_LEN, ELGAMAL_PUBKEY_LEN},
        macros::{impl_from_bytes, impl_from_str},
    },
    base64::{prelude::BASE64_STANDARD, Engine},
    bytemuck::Zeroable,
    core::fmt,
};

/// Maximum length of a base-64 encoded ElGamal public key
const ELGAMAL_PUBKEY_MAX_BASE64_LEN: usize = 44;

/// Maximum length of a base-64 encoded ElGamal ciphertext
const ELGAMAL_CIPHERTEXT_MAX_BASE64_LEN: usize = 88;

/// Maximum length of a base-64 encoded ElGamal decrypt handle
const DECRYPT_HANDLE_MAX_BASE64_LEN: usize = 44;

/// The `ElGamalCiphertext` type as a `Pod`.
#[derive(Clone, Copy, bytemuck_derive::Pod, bytemuck_derive::Zeroable, PartialEq, Eq)]
#[repr(transparent)]
pub struct PodElGamalCiphertext(pub [u8; ELGAMAL_CIPHERTEXT_LEN]);

impl fmt::Debug for PodElGamalCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl fmt::Display for PodElGamalCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.0))
    }
}

impl Default for PodElGamalCiphertext {
    fn default() -> Self {
        Self::zeroed()
    }
}

impl_from_str!(
    TYPE = PodElGamalCiphertext,
    BYTES_LEN = ELGAMAL_CIPHERTEXT_LEN,
    BASE64_LEN = ELGAMAL_CIPHERTEXT_MAX_BASE64_LEN
);

impl_from_bytes!(
    TYPE = PodElGamalCiphertext,
    BYTES_LEN = ELGAMAL_CIPHERTEXT_LEN
);

#[cfg(feature = "serde")]
impl_serde_base64!(TYPE = PodElGamalCiphertext);

/// The `ElGamalPubkey` type as a `Pod`.
#[derive(Clone, Copy, Default, bytemuck_derive::Pod, bytemuck_derive::Zeroable, PartialEq, Eq)]
#[repr(transparent)]
pub struct PodElGamalPubkey(pub [u8; ELGAMAL_PUBKEY_LEN]);

impl fmt::Debug for PodElGamalPubkey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl fmt::Display for PodElGamalPubkey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.0))
    }
}

impl_from_str!(
    TYPE = PodElGamalPubkey,
    BYTES_LEN = ELGAMAL_PUBKEY_LEN,
    BASE64_LEN = ELGAMAL_PUBKEY_MAX_BASE64_LEN
);

impl_from_bytes!(TYPE = PodElGamalPubkey, BYTES_LEN = ELGAMAL_PUBKEY_LEN);

#[cfg(feature = "serde")]
impl_serde_base64!(TYPE = PodElGamalPubkey);

/// The `DecryptHandle` type as a `Pod`.
#[derive(Clone, Copy, Default, bytemuck_derive::Pod, bytemuck_derive::Zeroable, PartialEq, Eq)]
#[repr(transparent)]
pub struct PodDecryptHandle(pub [u8; DECRYPT_HANDLE_LEN]);

impl fmt::Debug for PodDecryptHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl fmt::Display for PodDecryptHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.0))
    }
}

impl_from_str!(
    TYPE = PodDecryptHandle,
    BYTES_LEN = DECRYPT_HANDLE_LEN,
    BASE64_LEN = DECRYPT_HANDLE_MAX_BASE64_LEN
);

impl_from_bytes!(TYPE = PodDecryptHandle, BYTES_LEN = DECRYPT_HANDLE_LEN);

#[cfg(feature = "serde")]
impl_serde_base64!(TYPE = PodDecryptHandle);

/// An `ElGamalPubkey` that encodes `None` as all `0`, meant to be usable as a
/// `Pod` type.
#[derive(
    Clone, Copy, Debug, Default, bytemuck_derive::Pod, bytemuck_derive::Zeroable, PartialEq, Eq,
)]
#[repr(transparent)]
pub struct OptionalNonZeroElGamalPubkey(PodElGamalPubkey);

impl OptionalNonZeroElGamalPubkey {
    pub fn equals(&self, other: &PodElGamalPubkey) -> bool {
        &self.0 == other
    }
}

impl TryFrom<Option<PodElGamalPubkey>> for OptionalNonZeroElGamalPubkey {
    type Error = crate::errors::ParseError;

    fn try_from(p: Option<PodElGamalPubkey>) -> Result<Self, Self::Error> {
        match p {
            None => Ok(Self(PodElGamalPubkey::default())),
            Some(elgamal_pubkey) => {
                if elgamal_pubkey == PodElGamalPubkey::default() {
                    Err(crate::errors::ParseError::InvalidArgument)
                } else {
                    Ok(Self(elgamal_pubkey))
                }
            }
        }
    }
}

impl From<OptionalNonZeroElGamalPubkey> for Option<PodElGamalPubkey> {
    fn from(p: OptionalNonZeroElGamalPubkey) -> Self {
        if p.0 == PodElGamalPubkey::default() {
            None
        } else {
            Some(p.0)
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for OptionalNonZeroElGamalPubkey {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if self.0 == PodElGamalPubkey::default() {
            s.serialize_none()
        } else {
            s.serialize_some(&self.0)
        }
    }
}

#[cfg(feature = "serde")]
struct OptionalNonZeroElGamalPubkeyVisitor;

#[cfg(feature = "serde")]
impl<'de> serde::de::Visitor<'de> for OptionalNonZeroElGamalPubkeyVisitor {
    type Value = OptionalNonZeroElGamalPubkey;

    fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
        formatter.write_str("an ElGamal public key as base64 or `null`")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let elgamal_pubkey: PodElGamalPubkey =
            core::str::FromStr::from_str(v).map_err(serde::de::Error::custom)?;
        OptionalNonZeroElGamalPubkey::try_from(Some(elgamal_pubkey))
            .map_err(serde::de::Error::custom)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(OptionalNonZeroElGamalPubkey::default())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for OptionalNonZeroElGamalPubkey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(OptionalNonZeroElGamalPubkeyVisitor)
    }
}

#[cfg(test)]
mod tests {
    use {super::*, solana_zk_sdk::encryption::elgamal::ElGamalKeypair, std::str::FromStr};

    #[test]
    fn elgamal_pubkey_fromstr() {
        let elgamal_keypair = ElGamalKeypair::new_rand();
        let expected_elgamal_pubkey = PodElGamalPubkey(elgamal_keypair.pubkey().to_bytes());

        let elgamal_pubkey_base64_str = format!("{}", expected_elgamal_pubkey);
        let computed_elgamal_pubkey =
            PodElGamalPubkey::from_str(&elgamal_pubkey_base64_str).unwrap();

        assert_eq!(expected_elgamal_pubkey, computed_elgamal_pubkey);
    }

    #[test]
    fn elgamal_ciphertext_fromstr() {
        let elgamal_keypair = ElGamalKeypair::new_rand();
        let expected_elgamal_ciphertext =
            PodElGamalCiphertext(elgamal_keypair.pubkey().encrypt(0_u64).to_bytes());

        let elgamal_ciphertext_base64_str = format!("{}", expected_elgamal_ciphertext);
        let computed_elgamal_ciphertext =
            PodElGamalCiphertext::from_str(&elgamal_ciphertext_base64_str).unwrap();

        assert_eq!(expected_elgamal_ciphertext, computed_elgamal_ciphertext);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_elgamal_pubkey_serde() {
        let elgamal_keypair = ElGamalKeypair::new_rand();
        let expected_pubkey = PodElGamalPubkey(elgamal_keypair.pubkey().to_bytes());

        let serialized = serde_json::to_string(&expected_pubkey).unwrap();
        assert_eq!(serialized, format!("\"{}\"", expected_pubkey));

        let deserialized: PodElGamalPubkey = serde_json::from_str(&serialized).unwrap();
        assert_eq!(expected_pubkey, deserialized);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_elgamal_ciphertext_serde() {
        let elgamal_keypair = ElGamalKeypair::new_rand();
        let expected_ciphertext =
            PodElGamalCiphertext(elgamal_keypair.pubkey().encrypt(0_u64).to_bytes());

        let serialized = serde_json::to_string(&expected_ciphertext).unwrap();
        assert_eq!(serialized, format!("\"{}\"", expected_ciphertext));

        let deserialized: PodElGamalCiphertext = serde_json::from_str(&serialized).unwrap();
        assert_eq!(expected_ciphertext, deserialized);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_decrypt_handle_serde() {
        let expected_handle = PodDecryptHandle([42u8; DECRYPT_HANDLE_LEN]);

        let serialized = serde_json::to_string(&expected_handle).unwrap();
        assert_eq!(serialized, format!("\"{}\"", expected_handle));

        let deserialized: PodDecryptHandle = serde_json::from_str(&serialized).unwrap();
        assert_eq!(expected_handle, deserialized);
    }

    #[test]
    fn test_optional_non_zero_elgamal_pubkey_conversions() {
        let elgamal_keypair = ElGamalKeypair::new_rand();
        let pubkey = PodElGamalPubkey(elgamal_keypair.pubkey().to_bytes());

        // Test valid Some
        let opt_pubkey = OptionalNonZeroElGamalPubkey::try_from(Some(pubkey)).unwrap();
        assert!(opt_pubkey.equals(&pubkey));
        assert_eq!(Option::<PodElGamalPubkey>::from(opt_pubkey), Some(pubkey));

        // Test valid None
        let opt_none = OptionalNonZeroElGamalPubkey::try_from(None).unwrap();
        assert!(opt_none.equals(&PodElGamalPubkey::default()));
        assert_eq!(Option::<PodElGamalPubkey>::from(opt_none), None);

        // Test Invalid Argument (passing all zeros inside Some)
        let err =
            OptionalNonZeroElGamalPubkey::try_from(Some(PodElGamalPubkey::default())).unwrap_err();
        assert_eq!(err, crate::errors::ParseError::InvalidArgument);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_optional_non_zero_elgamal_pubkey_serde_some() {
        let elgamal_keypair = ElGamalKeypair::new_rand();
        let pubkey = PodElGamalPubkey(elgamal_keypair.pubkey().to_bytes());
        let expected = OptionalNonZeroElGamalPubkey::try_from(Some(pubkey)).unwrap();

        // Serialize should format as a base64 string
        let serialized = serde_json::to_string(&expected).unwrap();
        assert_eq!(serialized, format!("\"{}\"", pubkey));

        let deserialized: OptionalNonZeroElGamalPubkey = serde_json::from_str(&serialized).unwrap();
        assert_eq!(expected, deserialized);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_optional_non_zero_elgamal_pubkey_serde_none() {
        let expected = OptionalNonZeroElGamalPubkey::try_from(None).unwrap();

        // Serialize should format directly to `null`
        let serialized = serde_json::to_string(&expected).unwrap();
        assert_eq!(serialized, "null");

        let deserialized: OptionalNonZeroElGamalPubkey = serde_json::from_str(&serialized).unwrap();
        assert_eq!(expected, deserialized);
    }
}
