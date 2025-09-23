use {
    crate::encryption::pedersen::{WasmPedersenCommitment, WasmPedersenOpening},
    solana_zk_sdk::encryption::elgamal::{
        DecryptHandle, ElGamalCiphertext, ElGamalKeypair, ElGamalPubkey, ElGamalSecretKey,
    },
    wasm_bindgen::prelude::{wasm_bindgen, JsValue},
};

#[wasm_bindgen(js_name = "ElGamalPubkey")]
pub struct WasmElGamalPubkey {
    pub(crate) inner: ElGamalPubkey,
}

crate::conversion::impl_inner_conversion!(WasmElGamalPubkey, ElGamalPubkey);

#[wasm_bindgen]
impl WasmElGamalPubkey {
    /// Creates an ElGamal public key from a secret key.
    #[wasm_bindgen(js_name = "fromSecretKey")]
    pub fn from_secret_key(secret_key: &WasmElGamalSecretKey) -> Self {
        Self {
            inner: ElGamalPubkey::new(secret_key),
        }
    }

    /// Deserializes an ElGamal public key from a byte slice.
    /// Throws an error if the bytes are invalid.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &[u8]) -> Result<WasmElGamalPubkey, JsValue> {
        ElGamalPubkey::try_from(bytes)
            .map(|inner| Self { inner })
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Serializes the ElGamal public key to a byte array.
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Vec<u8> {
        let bytes: [u8; 32] = self.inner.into();
        bytes.to_vec()
    }

    /// Encrypts a 64-bit amount using the public key.
    #[wasm_bindgen(js_name = "encryptU64")]
    pub fn encrypt_u64(&self, amount: u64) -> WasmElGamalCiphertext {
        self.inner.encrypt(amount).into()
    }
}

#[wasm_bindgen(js_name = "ElGamalSecretKey")]
pub struct WasmElGamalSecretKey {
    pub(crate) inner: ElGamalSecretKey,
}

crate::conversion::impl_inner_conversion!(WasmElGamalSecretKey, ElGamalSecretKey);

#[wasm_bindgen]
impl WasmElGamalSecretKey {
    /// Creates a new, random ElGamal secret key.
    #[wasm_bindgen(constructor)]
    pub fn new_rand() -> Self {
        Self {
            inner: ElGamalSecretKey::new_rand(),
        }
    }

    /// Deserializes an ElGamal secret key from a byte slice.
    /// Throws an error if the bytes are invalid.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &[u8]) -> Result<WasmElGamalSecretKey, JsValue> {
        ElGamalSecretKey::try_from(bytes)
            .map(|inner| Self { inner })
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Serializes the ElGamal secret key to a byte array.
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.as_bytes().to_vec()
    }

    /// Decrypts an ElGamal ciphertext.
    /// Returns the decrypted amount as a u64, or `undefined` if decryption fails.
    #[wasm_bindgen(js_name = "decrypt")]
    pub fn decrypt(&self, ciphertext: &WasmElGamalCiphertext) -> Option<u64> {
        self.inner.decrypt_u32(ciphertext)
    }
}

#[wasm_bindgen(js_name = "ElGamalKeypair")]
pub struct WasmElGamalKeypair {
    pub(crate) inner: ElGamalKeypair,
}

crate::conversion::impl_inner_conversion!(WasmElGamalKeypair, ElGamalKeypair);

#[wasm_bindgen]
impl WasmElGamalKeypair {
    /// Creates a new, random ElGamal keypair.
    #[wasm_bindgen(constructor)]
    pub fn new_rand() -> Self {
        Self {
            inner: ElGamalKeypair::new_rand(),
        }
    }

    /// Creates an ElGamal keypair from a secret key.
    #[wasm_bindgen(js_name = "fromSecretKey")]
    pub fn from_secret_key(secret_key: &WasmElGamalSecretKey) -> Self {
        Self {
            inner: ElGamalKeypair::new(secret_key.inner.clone()),
        }
    }

    /// Returns the public key of the keypair.
    pub fn pubkey(&self) -> WasmElGamalPubkey {
        WasmElGamalPubkey {
            inner: *self.inner.pubkey(),
        }
    }

    /// Returns the secret key of the keypair.
    pub fn secret(&self) -> WasmElGamalSecretKey {
        WasmElGamalSecretKey {
            inner: self.inner.secret().clone(),
        }
    }
}

#[wasm_bindgen(js_name = "ElGamalCiphertext")]
pub struct WasmElGamalCiphertext {
    pub(crate) inner: ElGamalCiphertext,
}

crate::conversion::impl_inner_conversion!(WasmElGamalCiphertext, ElGamalCiphertext);

#[wasm_bindgen]
impl WasmElGamalCiphertext {
    /// Deserializes an ElGamal ciphertext from a byte slice.
    /// Returns `undefined` if the bytes are invalid.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &[u8]) -> Option<WasmElGamalCiphertext> {
        ElGamalCiphertext::from_bytes(bytes).map(|inner| Self { inner })
    }

    /// Serializes the ElGamal ciphertext to a byte array.
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }

    /// Returns the commitment component of the ciphertext.
    pub fn commitment(&self) -> WasmPedersenCommitment {
        WasmPedersenCommitment {
            inner: self.inner.commitment,
        }
    }

    /// Returns the decryption handle component of the ciphertext.
    pub fn handle(&self) -> WasmDecryptHandle {
        WasmDecryptHandle {
            inner: self.inner.handle,
        }
    }
}

#[wasm_bindgen(js_name = "DecryptHandle")]
pub struct WasmDecryptHandle {
    pub(crate) inner: DecryptHandle,
}

crate::conversion::impl_inner_conversion!(WasmDecryptHandle, DecryptHandle);

#[wasm_bindgen]
impl WasmDecryptHandle {
    /// Deserializes a decryption handle from a byte slice.
    /// Returns `undefined` if the bytes are invalid.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(bytes: &[u8]) -> Option<WasmDecryptHandle> {
        DecryptHandle::from_bytes(bytes).map(|inner| Self { inner })
    }

    /// Serializes the decryption handle to a byte array.
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use {super::*, wasm_bindgen_test::*};

    #[wasm_bindgen_test]
    fn test_elgamal_keypair_creation_and_accessors() {
        let secret = WasmElGamalSecretKey::new_rand();
        let keypair = WasmElGamalKeypair::from_secret_key(&secret);

        let pubkey = keypair.pubkey();
        let derived_pubkey = WasmElGamalPubkey::from_secret_key(&secret);

        assert_eq!(pubkey.to_bytes(), derived_pubkey.to_bytes());
        assert_eq!(secret.to_bytes(), keypair.secret().to_bytes());

        let rand_keypair = WasmElGamalKeypair::new_rand();
        assert_ne!(rand_keypair.secret().to_bytes(), secret.to_bytes());
    }

    #[wasm_bindgen_test]
    fn test_pubkey_and_secretkey_bytes_roundtrip() {
        let keypair = WasmElGamalKeypair::new_rand();
        let secret = keypair.secret();
        let pubkey = keypair.pubkey();

        // Secret Key roundtrip
        let secret_bytes = secret.to_bytes();
        let recovered_secret = WasmElGamalSecretKey::from_bytes(&secret_bytes).unwrap();
        assert_eq!(secret.inner, recovered_secret.inner);

        // Public Key roundtrip
        let pubkey_bytes = pubkey.to_bytes();
        let recovered_pubkey = WasmElGamalPubkey::from_bytes(&pubkey_bytes).unwrap();
        assert_eq!(pubkey.inner, recovered_pubkey.inner);
    }

    #[wasm_bindgen_test]
    fn test_encrypt_decrypt_cycle() {
        let amount_to_encrypt: u64 = 55;
        let keypair = WasmElGamalKeypair::new_rand();
        let pubkey = keypair.pubkey();
        let secret_key = keypair.secret();

        let ciphertext = pubkey.encrypt_u64(amount_to_encrypt);
        let decrypted_amount = secret_key.decrypt(&ciphertext);
        assert_eq!(decrypted_amount, Some(amount_to_encrypt));
    }

    #[wasm_bindgen_test]
    fn test_ciphertext_and_handle_bytes_roundtrip() {
        let keypair = WasmElGamalKeypair::new_rand();
        let ciphertext = keypair.pubkey().encrypt_u64(123);

        // Ciphertext roundtrip
        let ciphertext_bytes = ciphertext.to_bytes();
        let recovered_ciphertext = WasmElGamalCiphertext::from_bytes(&ciphertext_bytes).unwrap();
        assert_eq!(ciphertext.inner, recovered_ciphertext.inner);

        // Handle roundtrip
        let handle = ciphertext.handle();
        let handle_bytes = handle.to_bytes();
        let recovered_handle = WasmDecryptHandle::from_bytes(&handle_bytes).unwrap();
        assert_eq!(handle.inner, recovered_handle.inner);

        // Commitment roundtrip
        let commitment = ciphertext.commitment();
        let commitment_bytes = commitment.to_bytes();
        let recovered_commitment =
            crate::encryption::pedersen::WasmPedersenCommitment::from_bytes(&commitment_bytes)
                .unwrap();
        assert_eq!(commitment.inner, recovered_commitment.inner);
    }

    #[wasm_bindgen_test]
    fn test_decryption_with_wrong_key_fails() {
        let amount: u64 = 100;

        let keypair1 = WasmElGamalKeypair::new_rand();
        let keypair2 = WasmElGamalKeypair::new_rand(); // A different keypair

        let ciphertext = keypair1.pubkey().encrypt_u64(amount);
        let decrypted_result = keypair2.secret().decrypt(&ciphertext);
        assert!(decrypted_result.is_none());
    }

    #[wasm_bindgen_test]
    fn test_elgamal_encryption_is_not_deterministic() {
        let keypair = WasmElGamalKeypair::new_rand();
        let pubkey = keypair.pubkey();
        let amount: u64 = 77;

        let ciphertext1 = pubkey.encrypt_u64(amount);
        let ciphertext2 = pubkey.encrypt_u64(amount);

        // Two encryptions of the same amount should not be equal due to random openings
        assert_ne!(ciphertext1.to_bytes(), ciphertext2.to_bytes());
    }

    #[wasm_bindgen_test]
    fn test_from_bytes_with_invalid_input() {
        let short_pubkey = vec![0; 31];
        assert!(WasmElGamalPubkey::from_bytes(&short_pubkey).is_err());
        let long_pubkey = vec![0; 33];
        assert!(WasmElGamalPubkey::from_bytes(&long_pubkey).is_err());
        let invalid_pubkey = vec![0xFF; 32];
        assert!(WasmElGamalPubkey::from_bytes(&invalid_pubkey).is_err());

        let short_secret = vec![0; 31];
        assert!(WasmElGamalSecretKey::from_bytes(&short_secret).is_err());
        let long_secret = vec![0; 33];
        assert!(WasmElGamalSecretKey::from_bytes(&long_secret).is_err());

        let short_ciphertext = vec![0; 63];
        assert!(WasmElGamalCiphertext::from_bytes(&short_ciphertext).is_none());
        let long_ciphertext = vec![0; 65];
        assert!(WasmElGamalCiphertext::from_bytes(&long_ciphertext).is_none());
        let invalid_ciphertext = vec![0xFF; 64];
        assert!(WasmElGamalCiphertext::from_bytes(&invalid_ciphertext).is_none());

        let short_handle = vec![0; 31];
        assert!(WasmDecryptHandle::from_bytes(&short_handle).is_none());
        let long_handle = vec![0; 33];
        assert!(WasmDecryptHandle::from_bytes(&long_handle).is_none());
        let invalid_handle = vec![0xFF; 32];
        assert!(WasmDecryptHandle::from_bytes(&invalid_handle).is_none());
    }
}
