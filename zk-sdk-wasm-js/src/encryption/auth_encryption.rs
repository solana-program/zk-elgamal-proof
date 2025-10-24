use {
    js_sys::Uint8Array,
    solana_zk_sdk::encryption::{auth_encryption, AE_CIPHERTEXT_LEN, AE_KEY_LEN},
    wasm_bindgen::prelude::{wasm_bindgen, JsValue},
};

#[wasm_bindgen]
pub struct AeKey {
    pub(crate) inner: auth_encryption::AeKey,
}

crate::conversion::impl_inner_conversion!(AeKey, auth_encryption::AeKey);

#[wasm_bindgen]
impl AeKey {
    /// Creates a new, random authenticated encryption key.
    #[wasm_bindgen(constructor)]
    pub fn new_rand() -> Self {
        Self {
            inner: auth_encryption::AeKey::new_rand(),
        }
    }

    /// Deserializes an AeKey from a byte slice.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(uint8_array: Uint8Array) -> Result<AeKey, JsValue> {
        if uint8_array.length() as usize != AE_KEY_LEN {
            return Err(JsValue::from_str(&format!(
                "Invalid byte length for AeKey: expected {}, got {}",
                AE_KEY_LEN,
                uint8_array.length()
            )));
        }

        let mut bytes = [0u8; AE_KEY_LEN];
        uint8_array.copy_to(&mut bytes);

        auth_encryption::AeKey::try_from(bytes.as_ref())
            .map(|inner| Self { inner })
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Serializes the AeKey to a byte array.
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Vec<u8> {
        // Clone is needed here because the zk-sdk implements only `From<AeKey>` for
        // `[u8; AE_KEY_LEN]` and not `From<&AeKey>`.
        // TODO: Consider implementing `From<&AeKey>` for `[u8; AE_KEY_LEN]`.
        let bytes: [u8; AE_KEY_LEN] = self.inner.clone().into();
        bytes.to_vec()
    }

    /// Encrypts a 64-bit amount.
    #[wasm_bindgen]
    pub fn encrypt(&self, amount: u64) -> AeCiphertext {
        self.inner.encrypt(amount).into()
    }

    /// Decrypts a ciphertext. Returns the amount if successful, otherwise `undefined`.
    #[wasm_bindgen]
    pub fn decrypt(&self, ciphertext: &AeCiphertext) -> Result<u64, JsValue> {
        self.inner.decrypt(&ciphertext.inner).ok_or_else(|| {
            JsValue::from_str(
                "Decryption failed: The ciphertext may be tampered or the key incorrect.",
            )
        })
    }
}

#[wasm_bindgen]
pub struct AeCiphertext {
    pub(crate) inner: auth_encryption::AeCiphertext,
}

crate::conversion::impl_inner_conversion!(AeCiphertext, auth_encryption::AeCiphertext);

#[wasm_bindgen]
impl AeCiphertext {
    /// Deserializes an AeCiphertext from a byte slice.
    #[wasm_bindgen(js_name = "fromBytes")]
    pub fn from_bytes(uint8_array: Uint8Array) -> Option<AeCiphertext> {
        if uint8_array.length() as usize != AE_CIPHERTEXT_LEN {
            return None;
        }

        let mut bytes = [0u8; AE_CIPHERTEXT_LEN];
        uint8_array.copy_to(&mut bytes);

        auth_encryption::AeCiphertext::from_bytes(&bytes).map(|inner| Self { inner })
    }

    /// Serializes the AeCiphertext to a byte array.
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }

    /// Decrypts the ciphertext. Returns the amount if successful, otherwise `undefined`.
    #[wasm_bindgen]
    pub fn decrypt(&self, key: &AeKey) -> Option<u64> {
        self.inner.decrypt(key)
    }
}

#[cfg(test)]
mod tests {
    use {super::*, wasm_bindgen_test::*};

    #[wasm_bindgen_test]
    fn test_ae_key_roundtrip() {
        let key = AeKey::new_rand();
        let key_bytes = key.to_bytes();
        assert_eq!(key_bytes.len(), 16);
        let recovered_key = AeKey::from_bytes(Uint8Array::from(key_bytes.as_slice())).unwrap();
        assert_eq!(key.inner, recovered_key.inner);
    }

    #[wasm_bindgen_test]
    fn test_from_bytes_with_invalid_key() {
        let short_bytes = vec![0; 15];
        assert!(AeKey::from_bytes(Uint8Array::from(short_bytes.as_slice())).is_err());
        let long_bytes = vec![0; 17];
        assert!(AeKey::from_bytes(Uint8Array::from(long_bytes.as_slice())).is_err());
    }

    #[wasm_bindgen_test]
    fn test_encrypt_decrypt_cycle() {
        let key = AeKey::new_rand();
        let amount: u64 = 987654321;

        let ciphertext = key.encrypt(amount);
        let decrypted_amount_from_key = key.decrypt(&ciphertext);
        assert_eq!(decrypted_amount_from_key, Ok(amount));

        let decrypted_amount_from_ciphertext = ciphertext.decrypt(&key);
        assert_eq!(decrypted_amount_from_ciphertext, Some(amount));
    }

    #[wasm_bindgen_test]
    fn test_ciphertext_is_not_deterministic() {
        let key = AeKey::new_rand();
        let amount: u64 = 555;

        let ciphertext1 = key.encrypt(amount);
        let ciphertext2 = key.encrypt(amount);

        // Due to the random nonce, two encryptions of the same amount should not be equal
        assert_ne!(ciphertext1.to_bytes(), ciphertext2.to_bytes());
    }

    #[wasm_bindgen_test]
    fn test_decryption_with_wrong_key_fails() {
        let key1 = AeKey::new_rand();
        let key2 = AeKey::new_rand(); // A different key
        let amount: u64 = 100;
        let ciphertext = key1.encrypt(amount);

        // Attempt to decrypt with wrong key
        let result = key2.decrypt(&ciphertext);
        assert!(!result.is_ok());
    }
}
