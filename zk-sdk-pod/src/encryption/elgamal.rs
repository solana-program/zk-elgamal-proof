//! Plain Old Data types for the ElGamal encryption scheme.

#[cfg(feature = "serde")]
use crate::macros::impl_serde_base64;
use {
    crate::{
        encryption::{DECRYPT_HANDLE_LEN, ELGAMAL_CIPHERTEXT_LEN, ELGAMAL_PUBKEY_LEN},
        macros::{impl_from_bytes, impl_from_str, impl_nullable},
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

impl_nullable!(
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

impl_nullable!(TYPE = PodElGamalPubkey, BYTES_LEN = ELGAMAL_PUBKEY_LEN);

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

impl_nullable!(TYPE = PodDecryptHandle, BYTES_LEN = DECRYPT_HANDLE_LEN);

#[cfg(feature = "serde")]
impl_serde_base64!(TYPE = PodDecryptHandle);

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

    #[cfg(feature = "serde")]
    #[test]
    fn test_maybe_null_elgamal_pubkey_serde_some() {
        use solana_nullable::MaybeNull;

        let elgamal_keypair = ElGamalKeypair::new_rand();
        let pubkey = PodElGamalPubkey(elgamal_keypair.pubkey().to_bytes());

        // Wrap the valid pubkey in MaybeNull
        let expected = MaybeNull::from(pubkey);

        // Serialize should format as a base64 string
        let serialized = serde_json::to_string(&expected).unwrap();
        assert_eq!(serialized, format!("\"{}\"", pubkey));

        let deserialized: MaybeNull<PodElGamalPubkey> = serde_json::from_str(&serialized).unwrap();
        assert_eq!(expected, deserialized);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_maybe_null_elgamal_pubkey_serde_none() {
        use solana_nullable::MaybeNull;

        // Default initializes to the None state (all zeros)
        let expected = MaybeNull::<PodElGamalPubkey>::default();

        // Serialize should format directly to `null`
        let serialized = serde_json::to_string(&expected).unwrap();
        assert_eq!(serialized, "null");

        let deserialized: MaybeNull<PodElGamalPubkey> = serde_json::from_str(&serialized).unwrap();
        assert_eq!(expected, deserialized);
    }
}
