//! Confidential balances key derivation.
//!
//! Derives the `(ElGamalKeypair, AeKey)` pair used by the Token-2022
//! confidential-balances extension from a single source of input key material
//! via a unified HKDF-SHA512 (RFC 5869) chain. The salt, info strings, and
//! signing message are protocol-identified (`solana-conf-bal/v1`) so that
//! independent reimplementations on any platform derive byte-identical keys.
//!
//! Callers have three entry points:
//!
//! - [`derive_confidential_keys`] — sign once with a Solana `Signer`, derive
//!   both keys.
//! - [`derive_confidential_keys_from_signature`] — when the caller already
//!   holds a signature over the canonical message (e.g. produced via a
//!   wallet-adapter signing flow or a KMS deterministic-sign call).
//! - [`derive_confidential_keys_from_ikm`] — when the caller has raw input
//!   key material from any other source (WebAuthn PRF output, Secure Enclave
//!   HMAC output, KMS `GenerateMac` output, a BIP39 seed, or HKDF over an
//!   Ed25519 seed).
//!
//! The shared HKDF chain is:
//!
//! ```text
//! prk         = HKDF-SHA512-Extract(salt = HKDF_SALT, ikm = adapter_output)
//! ae_key      = HKDF-Expand(prk, info = AE_HKDF_INFO,      L = 16)
//! elgamal_sk  = Scalar::from_bytes_mod_order_wide(
//!                   HKDF-Expand(prk, info = ELGAMAL_HKDF_INFO, L = 64)
//!               )
//! ```
//!
//! `public_seed` in the signing path is caller-controlled and granularity-
//! agnostic: pass a wallet pubkey for registry-aligned per-wallet keying, or
//! a token-account pubkey for per-account keying. The SDK does not enforce
//! either convention.

use {
    crate::{
        encryption::{
            auth_encryption::AeKey,
            elgamal::{ElGamalKeypair, ElGamalSecretKey},
        },
        errors::ElGamalError,
    },
    curve25519_dalek::scalar::Scalar,
    hkdf::Hkdf,
    sha2::Sha512,
    solana_signature::Signature,
    solana_signer::{Signer, SignerError},
    solana_zk_sdk_pod::encryption::AE_KEY_LEN,
    std::error,
    subtle::ConstantTimeEq,
    zeroize::Zeroizing,
};

/// HKDF salt for the confidential-balances key derivation. Identifies the
/// protocol, not the implementation: independent reimplementations on any
/// platform derive byte-identical keys from this constant.
pub const HKDF_SALT: &[u8] = b"solana-conf-bal/v1";

/// HKDF info string for the AES (`decryptable_available_balance` fast-path)
/// key.
pub const AE_HKDF_INFO: &[u8] = b"ae";

/// HKDF info string for the ElGamal secret scalar.
pub const ELGAMAL_HKDF_INFO: &[u8] = b"elgamal";

/// Minimum acceptable IKM length when calling
/// [`derive_confidential_keys_from_ikm`] directly. Matches the
/// `ELGAMAL_SECRET_KEY_LEN` floor used elsewhere in the SDK.
const MINIMUM_IKM_LEN: usize = 32;

/// Maximum acceptable IKM length when calling
/// [`derive_confidential_keys_from_ikm`] directly.
const MAXIMUM_IKM_LEN: usize = 65535;

/// Signs the canonical derivation message with `signer` and derives the
/// confidential-balances key pair.
///
/// The signed message is `HKDF_SALT || public_seed`. `public_seed` is
/// caller-controlled and granularity-agnostic; pass a wallet pubkey for
/// per-wallet keying or a token-account pubkey for per-account keying.
pub fn derive_confidential_keys(
    signer: &dyn Signer,
    public_seed: &[u8],
) -> Result<(ElGamalKeypair, AeKey), Box<dyn error::Error>> {
    let message = [HKDF_SALT, public_seed].concat();
    let signature = signer.try_sign_message(&message)?;

    // Some `Signer` implementations return the default signature, which is not
    // suitable for use as key material.
    if bool::from(signature.as_ref().ct_eq(Signature::default().as_ref())) {
        return Err(SignerError::Custom("Rejecting default signature".into()).into());
    }

    derive_confidential_keys_from_signature(&signature)
}

/// Derives the confidential-balances key pair from a precomputed signature
/// over the canonical derivation message.
pub fn derive_confidential_keys_from_signature(
    signature: &Signature,
) -> Result<(ElGamalKeypair, AeKey), Box<dyn error::Error>> {
    derive_confidential_keys_from_ikm(signature.as_ref()).map_err(Into::into)
}

/// Derives the confidential-balances key pair from raw input key material.
///
/// This is the universal entry point used by non-`Signer` adapters (WebAuthn
/// PRF, Secure Enclave HMAC, KMS HMAC, direct HKDF over an Ed25519 seed,
/// BIP39 mnemonic seed, etc.).
pub fn derive_confidential_keys_from_ikm(
    ikm: &[u8],
) -> Result<(ElGamalKeypair, AeKey), ElGamalError> {
    if ikm.len() < MINIMUM_IKM_LEN {
        return Err(ElGamalError::SeedLengthTooShort);
    }
    if ikm.len() > MAXIMUM_IKM_LEN {
        return Err(ElGamalError::SeedLengthTooLong);
    }

    let hkdf = Hkdf::<Sha512>::new(Some(HKDF_SALT), ikm);

    let mut ae_bytes = Zeroizing::new([0u8; AE_KEY_LEN]);
    hkdf.expand(AE_HKDF_INFO, ae_bytes.as_mut_slice())
        .map_err(|_| ElGamalError::SecretKeyDeserialization)?;
    let ae_key = AeKey::from(*ae_bytes);

    let mut elgamal_wide = Zeroizing::new([0u8; 64]);
    hkdf.expand(ELGAMAL_HKDF_INFO, elgamal_wide.as_mut_slice())
        .map_err(|_| ElGamalError::SecretKeyDeserialization)?;
    let elgamal_secret = ElGamalSecretKey::from(Scalar::from_bytes_mod_order_wide(&elgamal_wide));

    Ok((ElGamalKeypair::new(elgamal_secret), ae_key))
}

#[cfg(test)]
mod tests {
    use {
        super::*, crate::encryption::elgamal::ElGamalPubkey, solana_address::Address,
        solana_keypair::Keypair,
    };

    #[test]
    fn test_derive_confidential_keys_determinism() {
        let keypair = Keypair::new();
        let public_seed = [0x11u8; 32];

        let (kp_a, ae_a) = derive_confidential_keys(&keypair, &public_seed).unwrap();
        let (kp_b, ae_b) = derive_confidential_keys(&keypair, &public_seed).unwrap();

        assert_eq!(kp_a.secret().as_bytes(), kp_b.secret().as_bytes());
        assert_eq!(
            <[u8; AE_KEY_LEN]>::from(&ae_a),
            <[u8; AE_KEY_LEN]>::from(&ae_b)
        );
    }

    #[test]
    fn test_derive_confidential_keys_distinct_signers() {
        let kp1 = Keypair::new();
        let kp2 = Keypair::new();

        let (elgamal1, ae1) = derive_confidential_keys(&kp1, Address::default().as_ref()).unwrap();
        let (elgamal2, ae2) = derive_confidential_keys(&kp2, Address::default().as_ref()).unwrap();

        assert_ne!(elgamal1.secret().as_bytes(), elgamal2.secret().as_bytes());
        assert_ne!(
            <[u8; AE_KEY_LEN]>::from(&ae1),
            <[u8; AE_KEY_LEN]>::from(&ae2)
        );
    }

    #[test]
    fn test_derive_confidential_keys_signer_matches_signature() {
        // `derive_confidential_keys` and `_from_signature` over the
        // wallet-produced signature must yield byte-identical keys.
        let keypair = Keypair::new();
        let public_seed = [0x22u8; 32];

        let (kp_signer, ae_signer) = derive_confidential_keys(&keypair, &public_seed).unwrap();

        let message = [HKDF_SALT, public_seed.as_ref()].concat();
        let sig = keypair.sign_message(&message);
        let (kp_sig, ae_sig) = derive_confidential_keys_from_signature(&sig).unwrap();

        assert_eq!(kp_signer.secret().as_bytes(), kp_sig.secret().as_bytes());
        assert_eq!(
            <[u8; AE_KEY_LEN]>::from(&ae_signer),
            <[u8; AE_KEY_LEN]>::from(&ae_sig)
        );
    }

    #[test]
    fn test_derive_confidential_keys_from_ikm_known_vector() {
        // Canonical test vector for the unified HKDF-SHA512 spine.
        //
        // Inputs:
        //   ikm  = [0x42; 64]    (e.g. a 64-byte Ed25519 signature filled with 0x42)
        //   salt = b"solana-conf-bal/v1"
        //   info = b"ae" (for AeKey) or b"elgamal" (for ElGamal scalar wide)
        let ikm = [0x42u8; 64];
        let (kp, ae) = derive_confidential_keys_from_ikm(&ikm).unwrap();

        let expected_ae: [u8; AE_KEY_LEN] = [
            0x1b, 0x29, 0x77, 0x8a, 0x34, 0x93, 0xda, 0xb2, 0x18, 0xc2, 0x4e, 0x87, 0x14, 0x4b,
            0xe4, 0x3d,
        ];
        let expected_elgamal: [u8; 32] = [
            0x71, 0x6d, 0x24, 0x31, 0xfa, 0x74, 0xfc, 0x1c, 0x48, 0xff, 0xb9, 0xb9, 0x97, 0x2b,
            0x0b, 0xe2, 0xf0, 0xb2, 0x9a, 0xb7, 0x55, 0x08, 0x1f, 0x2e, 0xa3, 0x5d, 0x3c, 0x74,
            0xf4, 0x42, 0x19, 0x0e,
        ];

        assert_eq!(
            <[u8; AE_KEY_LEN]>::from(&ae),
            expected_ae,
            "AeKey HKDF vector drift; computed {:02x?}",
            <[u8; AE_KEY_LEN]>::from(&ae)
        );
        assert_eq!(
            kp.secret().as_bytes(),
            &expected_elgamal,
            "ElGamal HKDF vector drift; computed {:02x?}",
            kp.secret().as_bytes()
        );
    }

    #[test]
    fn test_derive_confidential_keys_from_ikm_rejects_short() {
        let too_short = vec![0u8; MINIMUM_IKM_LEN - 1];
        assert!(matches!(
            derive_confidential_keys_from_ikm(&too_short),
            Err(ElGamalError::SeedLengthTooShort)
        ));
    }

    #[test]
    fn test_derive_confidential_keys_from_ikm_rejects_long() {
        let too_long = vec![0u8; MAXIMUM_IKM_LEN + 1];
        assert!(matches!(
            derive_confidential_keys_from_ikm(&too_long),
            Err(ElGamalError::SeedLengthTooLong)
        ));
    }

    #[test]
    fn test_derive_confidential_keys_keypair_consistent() {
        // The returned ElGamal keypair's public key MUST equal
        // `ElGamalPubkey::new(secret)` so callers can rely on the keypair
        // invariant.
        let ikm = [0x33u8; 64];
        let (kp, _ae) = derive_confidential_keys_from_ikm(&ikm).unwrap();
        assert_eq!(*kp.pubkey(), ElGamalPubkey::new(kp.secret()));
    }
}
