//! Authenticated encryption implementation.
//!
//! This module is a simple wrapper of the `Aes128GcmSiv` implementation
//! specialized for SPL Token-2022 program where the plaintext is always a `u64`
//! number.
use {
    crate::errors::AuthenticatedEncryptionError,
    aes_gcm_siv::{
        aead::{Aead, KeyInit},
        Aes128GcmSiv,
    },
    base64::{prelude::BASE64_STANDARD, Engine},
    hkdf::Hkdf,
    rand::{rngs::OsRng, Rng},
    sha2::Sha512,
    sha3::{Digest, Sha3_512},
    solana_derivation_path::DerivationPath,
    solana_seed_derivable::SeedDerivable,
    solana_seed_phrase::generate_seed_from_seed_phrase_and_passphrase,
    solana_signature::Signature,
    solana_signer::{EncodableKey, Signer, SignerError},
    solana_zk_sdk_pod::encryption::{
        auth_encryption::PodAeCiphertext, AE_CIPHERTEXT_LEN, AE_KEY_LEN,
    },
    std::{
        convert::TryInto,
        error, fmt,
        io::{Read, Write},
    },
    subtle::ConstantTimeEq,
    zeroize::{Zeroize, Zeroizing},
};

/// HKDF salt used when deriving an `AeKey`. Versioned so that future revisions
/// of the key derivation scheme can coexist with the current one by bumping the
/// `:vN` suffix.
const AE_HKDF_SALT: &[u8] = b"solana-zk-sdk:AeKey:v1:hkdf-sha512";

/// HKDF info string used to bind the expanded output to the `AeKey` key type.
/// Combined with the salt this provides domain separation against ElGamal
/// derivation even when both share the same input key material.
const AE_HKDF_INFO: &[u8] = b"AeKey";

/// Byte length of an authenticated encryption nonce component
const NONCE_LEN: usize = 12;

/// Byte length of an authenticated encryption ciphertext component
const CIPHERTEXT_LEN: usize = 24;

struct AuthenticatedEncryption;
impl AuthenticatedEncryption {
    /// Generates an authenticated encryption key.
    ///
    /// This function is randomized. It internally samples a 128-bit key using `OsRng`.
    fn keygen() -> AeKey {
        AeKey(OsRng.gen::<[u8; AE_KEY_LEN]>())
    }

    /// On input of an authenticated encryption key and an amount, the function returns a
    /// corresponding authenticated encryption ciphertext.
    fn encrypt(key: &AeKey, balance: u64) -> AeCiphertext {
        let plaintext = Zeroizing::new(balance.to_le_bytes());
        let nonce: Nonce = OsRng.gen::<[u8; NONCE_LEN]>();

        // The balance and the nonce have fixed length and therefore, encryption should not fail.
        let ciphertext = Aes128GcmSiv::new(&key.0.into())
            .encrypt(&nonce.into(), plaintext.as_ref())
            .expect("authenticated encryption");

        AeCiphertext {
            nonce,
            ciphertext: ciphertext.try_into().unwrap(),
        }
    }

    /// On input of an authenticated encryption key and a ciphertext, the function returns the
    /// originally encrypted amount.
    fn decrypt(key: &AeKey, ciphertext: &AeCiphertext) -> Option<u64> {
        let plaintext_result = Aes128GcmSiv::new(&key.0.into())
            .decrypt(&ciphertext.nonce.into(), ciphertext.ciphertext.as_ref());

        if let Ok(plaintext_vec) = plaintext_result {
            let plaintext = Zeroizing::new(plaintext_vec);
            if plaintext.len() == 8 {
                let mut amount_bytes = Zeroizing::new([0u8; 8]);
                amount_bytes.copy_from_slice(&plaintext);

                let amount = u64::from_le_bytes(*amount_bytes);
                Some(amount)
            } else {
                None
            }
        } else {
            None
        }
    }
}

#[derive(Clone, Zeroize, Eq, PartialEq)]
#[zeroize(drop)]
pub struct AeKey([u8; AE_KEY_LEN]);

impl AeKey {
    /// Deterministically derives an authenticated encryption key from a Solana signer and a public
    /// seed.
    ///
    /// This function exists for applications where a user may not wish to maintain a Solana signer
    /// and an authenticated encryption key separately. Instead, a user can derive the ElGamal
    /// keypair on-the-fly whenever encryption / decryption is needed.
    pub fn new_from_signer(
        signer: &dyn Signer,
        public_seed: &[u8],
    ) -> Result<Self, Box<dyn error::Error>> {
        let seed = Self::seed_from_signer(signer, public_seed)?;
        Self::from_seed(&seed)
    }

    /// Derive a seed from a Solana signer used to generate an authenticated encryption key.
    ///
    /// The signer is asked to sign the message `b"AeKey" || public_seed`. The
    /// resulting Ed25519 signature is fed into HKDF-SHA512 (RFC 5869) to
    /// produce 64 bytes of pseudorandom seed material suitable for
    /// [`AeKey::from_seed`].
    pub fn seed_from_signer(
        signer: &dyn Signer,
        public_seed: &[u8],
    ) -> Result<Vec<u8>, SignerError> {
        let message = [b"AeKey", public_seed].concat();
        let signature = signer.try_sign_message(&message)?;

        // Some `Signer` implementations return the default signature, which is not suitable for
        // use as key material
        if bool::from(signature.as_ref().ct_eq(Signature::default().as_ref())) {
            return Err(SignerError::Custom("Rejecting default signature".into()));
        }

        Ok(Self::seed_from_signature(&signature))
    }

    /// Derive an authenticated encryption key from a signature.
    pub fn new_from_signature(signature: &Signature) -> Result<Self, Box<dyn error::Error>> {
        let seed = Self::seed_from_signature(signature);
        Self::from_seed(&seed)
    }

    /// Derive a seed from a signature used to generate an authenticated
    /// encryption key.
    ///
    /// The signature is treated as input key material for HKDF-Extract
    /// (HKDF-SHA512, RFC 5869) using a versioned, domain-separated salt. The
    /// returned 64-byte pseudorandom key is then fed into [`AeKey::from_seed`]
    /// which performs the corresponding HKDF-Expand step.
    pub fn seed_from_signature(signature: &Signature) -> Vec<u8> {
        let (prk, _) = Hkdf::<Sha512>::extract(Some(AE_HKDF_SALT), signature.as_ref());
        prk.to_vec()
    }

    /// Derive an authenticated encryption key from a Solana signer using the
    /// legacy SHA3-512-based KDF.
    ///
    /// Retained only so wallets can recover keys for accounts that were
    /// provisioned under `solana-zk-sdk` versions that shipped the
    /// non-standard `Truncate-128(SHA3-512(...))` derivation. New code should
    /// use [`AeKey::new_from_signer`].
    #[deprecated(
        note = "Non-standard SHA3-512 KDF; new code should use `AeKey::new_from_signer`. \
                Retained for backward compatibility with accounts provisioned under \
                solana-zk-sdk versions prior to the HKDF-SHA512 migration. \
                See https://github.com/solana-program/zk-elgamal-proof/issues/35."
    )]
    #[allow(deprecated)]
    pub fn new_from_signer_legacy(
        signer: &dyn Signer,
        public_seed: &[u8],
    ) -> Result<Self, Box<dyn error::Error>> {
        let seed = Self::seed_from_signer_legacy(signer, public_seed)?;
        Self::from_seed_legacy(&seed)
    }

    /// Derive a seed from a Solana signer using the legacy SHA3-512 KDF.
    ///
    /// See [`AeKey::new_from_signer_legacy`] for context.
    #[deprecated(
        note = "Non-standard SHA3-512 KDF; new code should use `AeKey::seed_from_signer`. \
                Retained for backward compatibility. \
                See https://github.com/solana-program/zk-elgamal-proof/issues/35."
    )]
    #[allow(deprecated)]
    pub fn seed_from_signer_legacy(
        signer: &dyn Signer,
        public_seed: &[u8],
    ) -> Result<Vec<u8>, SignerError> {
        let message = [b"AeKey", public_seed].concat();
        let signature = signer.try_sign_message(&message)?;

        if bool::from(signature.as_ref().ct_eq(Signature::default().as_ref())) {
            return Err(SignerError::Custom("Rejecting default signature".into()));
        }

        Ok(Self::seed_from_signature_legacy(&signature))
    }

    /// Derive an authenticated encryption key from a raw signature using the
    /// legacy SHA3-512 KDF.
    ///
    /// See [`AeKey::new_from_signer_legacy`] for context.
    #[deprecated(
        note = "Non-standard SHA3-512 KDF; new code should use `AeKey::new_from_signature`. \
                Retained for backward compatibility. \
                See https://github.com/solana-program/zk-elgamal-proof/issues/35."
    )]
    #[allow(deprecated)]
    pub fn new_from_signature_legacy(signature: &Signature) -> Result<Self, Box<dyn error::Error>> {
        let seed = Self::seed_from_signature_legacy(signature);
        Self::from_seed_legacy(&seed)
    }

    /// Derive a seed from a signature using the legacy SHA3-512 KDF.
    ///
    /// See [`AeKey::new_from_signer_legacy`] for context.
    #[deprecated(
        note = "Non-standard SHA3-512 KDF; new code should use `AeKey::seed_from_signature`. \
                Retained for backward compatibility. \
                See https://github.com/solana-program/zk-elgamal-proof/issues/35."
    )]
    pub fn seed_from_signature_legacy(signature: &Signature) -> Vec<u8> {
        let mut hasher = Sha3_512::new();
        hasher.update(signature);
        let result = hasher.finalize();

        result.to_vec()
    }

    /// Derive an authenticated encryption key from a raw seed using the legacy
    /// SHA3-512 KDF.
    ///
    /// See [`AeKey::new_from_signer_legacy`] for context.
    #[deprecated(
        note = "Non-standard SHA3-512 KDF; new code should use `AeKey::from_seed`. \
                Retained for backward compatibility. \
                See https://github.com/solana-program/zk-elgamal-proof/issues/35."
    )]
    pub fn from_seed_legacy(seed: &[u8]) -> Result<Self, Box<dyn error::Error>> {
        const MINIMUM_SEED_LEN: usize = AE_KEY_LEN;
        const MAXIMUM_SEED_LEN: usize = 65535;

        if seed.len() < MINIMUM_SEED_LEN {
            return Err(AuthenticatedEncryptionError::SeedLengthTooShort.into());
        }
        if seed.len() > MAXIMUM_SEED_LEN {
            return Err(AuthenticatedEncryptionError::SeedLengthTooLong.into());
        }

        let mut hasher = Sha3_512::new();
        hasher.update(seed);
        let result = hasher.finalize();

        Ok(Self(result[..AE_KEY_LEN].try_into()?))
    }

    /// Derive an authenticated encryption key from a BIP39 mnemonic and
    /// passphrase using the legacy SHA3-512 KDF.
    ///
    /// See [`AeKey::new_from_signer_legacy`] for context.
    #[deprecated(
        note = "Non-standard SHA3-512 KDF; new code should use `<AeKey as SeedDerivable>::\
                from_seed_phrase_and_passphrase`. Retained for backward compatibility. \
                See https://github.com/solana-program/zk-elgamal-proof/issues/35."
    )]
    #[allow(deprecated)]
    pub fn from_seed_phrase_and_passphrase_legacy(
        seed_phrase: &str,
        passphrase: &str,
    ) -> Result<Self, Box<dyn error::Error>> {
        Self::from_seed_legacy(&generate_seed_from_seed_phrase_and_passphrase(
            seed_phrase,
            passphrase,
        ))
    }

    /// Generates a random authenticated encryption key.
    ///
    /// This function is randomized. It internally samples a 128-bit key using `OsRng`.
    pub fn new_rand() -> Self {
        AuthenticatedEncryption::keygen()
    }

    /// Encrypts an amount under the authenticated encryption key.
    pub fn encrypt(&self, amount: u64) -> AeCiphertext {
        AuthenticatedEncryption::encrypt(self, amount)
    }

    pub fn decrypt(&self, ciphertext: &AeCiphertext) -> Option<u64> {
        AuthenticatedEncryption::decrypt(self, ciphertext)
    }
}

impl fmt::Debug for AeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("AeKey").field(&"[REDACTED]").finish()
    }
}

impl EncodableKey for AeKey {
    fn read<R: Read>(reader: &mut R) -> Result<Self, Box<dyn error::Error>> {
        let bytes: [u8; AE_KEY_LEN] = serde_json::from_reader(reader)?;
        Ok(Self(bytes))
    }

    fn write<W: Write>(&self, writer: &mut W) -> Result<String, Box<dyn error::Error>> {
        let bytes = self.0;
        let json = serde_json::to_string(&bytes.to_vec())?;
        writer.write_all(&json.clone().into_bytes())?;
        Ok(json)
    }
}

impl SeedDerivable for AeKey {
    fn from_seed(seed: &[u8]) -> Result<Self, Box<dyn error::Error>> {
        const MINIMUM_SEED_LEN: usize = AE_KEY_LEN;
        const MAXIMUM_SEED_LEN: usize = 65535;

        if seed.len() < MINIMUM_SEED_LEN {
            return Err(AuthenticatedEncryptionError::SeedLengthTooShort.into());
        }
        if seed.len() > MAXIMUM_SEED_LEN {
            return Err(AuthenticatedEncryptionError::SeedLengthTooLong.into());
        }

        let hkdf = Hkdf::<Sha512>::new(Some(AE_HKDF_SALT), seed);
        let mut okm = [0u8; AE_KEY_LEN];
        hkdf.expand(AE_HKDF_INFO, &mut okm)
            .map_err(|_| AuthenticatedEncryptionError::Deserialization)?;

        Ok(Self(okm))
    }

    fn from_seed_and_derivation_path(
        _seed: &[u8],
        _derivation_path: Option<DerivationPath>,
    ) -> Result<Self, Box<dyn error::Error>> {
        Err(AuthenticatedEncryptionError::DerivationMethodNotSupported.into())
    }

    fn from_seed_phrase_and_passphrase(
        seed_phrase: &str,
        passphrase: &str,
    ) -> Result<Self, Box<dyn error::Error>> {
        Self::from_seed(&generate_seed_from_seed_phrase_and_passphrase(
            seed_phrase,
            passphrase,
        ))
    }
}

impl From<[u8; AE_KEY_LEN]> for AeKey {
    fn from(bytes: [u8; AE_KEY_LEN]) -> Self {
        Self(bytes)
    }
}

impl From<AeKey> for [u8; AE_KEY_LEN] {
    fn from(key: AeKey) -> Self {
        key.0
    }
}

impl From<&AeKey> for [u8; AE_KEY_LEN] {
    fn from(key: &AeKey) -> Self {
        key.0
    }
}

impl TryFrom<&[u8]> for AeKey {
    type Error = AuthenticatedEncryptionError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != AE_KEY_LEN {
            return Err(AuthenticatedEncryptionError::Deserialization);
        }
        bytes
            .try_into()
            .map(Self)
            .map_err(|_| AuthenticatedEncryptionError::Deserialization)
    }
}

/// For the purpose of encrypting balances for the spl token accounts, the nonce and ciphertext
/// sizes should always be fixed.
type Nonce = [u8; NONCE_LEN];
type Ciphertext = [u8; CIPHERTEXT_LEN];

/// Authenticated encryption nonce and ciphertext
#[derive(Clone, Copy, Debug, Default)]
pub struct AeCiphertext {
    nonce: Nonce,
    ciphertext: Ciphertext,
}
impl AeCiphertext {
    pub fn decrypt(&self, key: &AeKey) -> Option<u64> {
        AuthenticatedEncryption::decrypt(key, self)
    }

    pub fn to_bytes(&self) -> [u8; AE_CIPHERTEXT_LEN] {
        let mut buf = [0_u8; AE_CIPHERTEXT_LEN];
        buf[..NONCE_LEN].copy_from_slice(&self.nonce);
        buf[NONCE_LEN..].copy_from_slice(&self.ciphertext);
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<AeCiphertext> {
        if bytes.len() != AE_CIPHERTEXT_LEN {
            return None;
        }

        let nonce = bytes[..NONCE_LEN].try_into().ok()?;
        let ciphertext = bytes[NONCE_LEN..].try_into().ok()?;

        Some(AeCiphertext { nonce, ciphertext })
    }
}

impl fmt::Display for AeCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.to_bytes()))
    }
}

impl From<AeCiphertext> for PodAeCiphertext {
    fn from(decoded_ciphertext: AeCiphertext) -> Self {
        Self(decoded_ciphertext.to_bytes())
    }
}

impl TryFrom<PodAeCiphertext> for AeCiphertext {
    type Error = AuthenticatedEncryptionError;

    fn try_from(pod_ciphertext: PodAeCiphertext) -> Result<Self, Self::Error> {
        Self::from_bytes(&pod_ciphertext.0).ok_or(AuthenticatedEncryptionError::Deserialization)
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*, solana_address::Address, solana_keypair::Keypair,
        solana_signer::null_signer::NullSigner,
    };

    #[test]
    fn test_aes_encrypt_decrypt_correctness() {
        let key = AeKey::new_rand();
        let amount = 55;

        let ciphertext = key.encrypt(amount);
        let decrypted_amount = ciphertext.decrypt(&key).unwrap();

        assert_eq!(amount, decrypted_amount);
    }

    #[test]
    fn test_aes_new() {
        let keypair1 = Keypair::new();
        let keypair2 = Keypair::new();

        assert_ne!(
            AeKey::new_from_signer(&keypair1, Address::default().as_ref())
                .unwrap()
                .0,
            AeKey::new_from_signer(&keypair2, Address::default().as_ref())
                .unwrap()
                .0,
        );

        let null_signer = NullSigner::new(&Address::default());
        assert!(AeKey::new_from_signer(&null_signer, Address::default().as_ref()).is_err());
    }

    #[test]
    fn test_aes_key_from_seed() {
        let good_seed = vec![0; 32];
        assert!(AeKey::from_seed(&good_seed).is_ok());

        let too_short_seed = vec![0; 15];
        assert!(AeKey::from_seed(&too_short_seed).is_err());

        let too_long_seed = vec![0; 65536];
        assert!(AeKey::from_seed(&too_long_seed).is_err());
    }

    #[test]
    fn test_aes_key_from() {
        let key = AeKey::from_seed(&[0; 32]).unwrap();
        let key_bytes: [u8; AE_KEY_LEN] = AeKey::from_seed(&[0; 32]).unwrap().into();

        assert_eq!(key, AeKey::from(key_bytes));
    }

    #[test]
    fn test_aes_key_try_from() {
        let key = AeKey::from_seed(&[0; 32]).unwrap();
        let key_bytes: [u8; AE_KEY_LEN] = AeKey::from_seed(&[0; 32]).unwrap().into();

        assert_eq!(key, AeKey::try_from(key_bytes.as_slice()).unwrap());
    }

    #[test]
    fn test_aes_key_try_from_error() {
        let too_short_bytes = vec![0_u8; AE_KEY_LEN - 1];
        assert!(AeKey::try_from(too_short_bytes.as_slice()).is_err());

        let too_many_bytes = vec![0_u8; AE_KEY_LEN + 1];
        assert!(AeKey::try_from(too_many_bytes.as_slice()).is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails_decryption() {
        let key = AeKey::new_rand();
        let amount = 99_u64;

        let ciphertext = key.encrypt(amount);
        let mut tampered_bytes = ciphertext.to_bytes();

        // Flip the first bit of the actual ciphertext component
        tampered_bytes[NONCE_LEN] ^= 1;

        let tampered_ciphertext = AeCiphertext::from_bytes(&tampered_bytes).unwrap();
        assert!(tampered_ciphertext.decrypt(&key).is_none());
    }

    #[test]
    fn test_tampered_nonce_fails_decryption() {
        let key = AeKey::new_rand();
        let amount = 99_u64;

        let ciphertext = key.encrypt(amount);
        let mut tampered_bytes = ciphertext.to_bytes();

        // Flip the first bit of the nonce
        tampered_bytes[0] ^= 1;

        let tampered_ciphertext = AeCiphertext::from_bytes(&tampered_bytes).unwrap();
        assert!(tampered_ciphertext.decrypt(&key).is_none());
    }

    #[test]
    fn test_aes_key_from_into_ref() {
        // Verify `From<&AeKey> for [u8; AE_KEY_LEN]` returns the same bytes as
        // the owning version. This is what backs the wasm-js `to_bytes()`
        // no-clone path.
        let key = AeKey::from_seed(&[7; 32]).unwrap();
        let owned: [u8; AE_KEY_LEN] = key.clone().into();
        let borrowed: [u8; AE_KEY_LEN] = (&key).into();
        assert_eq!(owned, borrowed);
    }

    #[test]
    fn test_aekey_hkdf_determinism_from_signature() {
        let sig = Signature::from([0x42u8; 64]);
        let key_a = AeKey::new_from_signature(&sig).unwrap();
        let key_b = AeKey::new_from_signature(&sig).unwrap();
        assert_eq!(
            <[u8; AE_KEY_LEN]>::from(&key_a),
            <[u8; AE_KEY_LEN]>::from(&key_b),
        );
    }

    #[test]
    fn test_aekey_hkdf_differs_from_legacy() {
        // The HKDF and legacy SHA3-512 paths must produce different keys for
        // the same input — otherwise the legacy fallback would silently match
        // the new derivation and accounts could be mis-claimed as migrated.
        let sig = Signature::from([0x42u8; 64]);
        let new_key = AeKey::new_from_signature(&sig).unwrap();
        #[allow(deprecated)]
        let old_key = AeKey::new_from_signature_legacy(&sig).unwrap();
        assert_ne!(
            <[u8; AE_KEY_LEN]>::from(&new_key),
            <[u8; AE_KEY_LEN]>::from(&old_key),
        );
    }

    #[test]
    fn test_aekey_hkdf_known_vector_from_signature() {
        // Canonical test vector for the HKDF-SHA512 AeKey derivation.
        //
        // Inputs:
        //   signature = [0x42; 64]
        //   salt      = b"solana-zk-sdk:AeKey:v1:hkdf-sha512"
        //   info      = b"AeKey"
        //   L         = 16
        let sig = Signature::from([0x42u8; 64]);
        let key = AeKey::new_from_signature(&sig).unwrap();
        let bytes: [u8; AE_KEY_LEN] = (&key).into();
        let expected: [u8; AE_KEY_LEN] = [
            0xe7, 0x04, 0x81, 0x8f, 0x1c, 0x01, 0xb9, 0xbe, 0x2d, 0xb3, 0x99, 0x67, 0x7b, 0x7a,
            0x91, 0x53,
        ];
        assert_eq!(
            bytes, expected,
            "HKDF AeKey vector drift; computed {:02x?}",
            bytes
        );
    }

    #[test]
    fn test_aekey_legacy_known_vector_from_signature() {
        // Pinned canonical bytes for the SHA3-512 legacy derivation.
        // Inputs:
        //   signature = [0x42; 64]
        //   key       = Truncate-128(SHA3-512(SHA3-512(signature)))
        let sig = Signature::from([0x42u8; 64]);
        #[allow(deprecated)]
        let key = AeKey::new_from_signature_legacy(&sig).unwrap();
        let bytes: [u8; AE_KEY_LEN] = (&key).into();
        let expected: [u8; AE_KEY_LEN] = [
            0x06, 0x6b, 0x8d, 0xa6, 0x7e, 0x6f, 0x30, 0x1c, 0xab, 0x63, 0x4b, 0x60, 0x93, 0xca,
            0x8c, 0x35,
        ];
        assert_eq!(
            bytes, expected,
            "Legacy AeKey vector drift; computed {:02x?}",
            bytes
        );
    }

    #[test]
    fn test_aekey_hkdf_signer_matches_signature_path() {
        // `new_from_signer` should match `new_from_signature` applied to the
        // signature the signer would produce for the same message.
        let keypair = Keypair::new();
        let public_seed = [0x11u8; 32];
        let key_from_signer = AeKey::new_from_signer(&keypair, &public_seed).unwrap();

        let message = [b"AeKey", public_seed.as_ref()].concat();
        let sig = keypair.sign_message(&message);
        let key_from_sig = AeKey::new_from_signature(&sig).unwrap();

        assert_eq!(
            <[u8; AE_KEY_LEN]>::from(&key_from_signer),
            <[u8; AE_KEY_LEN]>::from(&key_from_sig),
        );
    }

    #[test]
    fn test_encryption_is_non_deterministic() {
        let key = AeKey::new_rand();
        let amount = 123_u64;

        let ciphertext1 = key.encrypt(amount);
        let ciphertext2 = key.encrypt(amount);

        assert_ne!(ciphertext1.to_bytes(), ciphertext2.to_bytes());
    }
}
