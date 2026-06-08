use {
    crate::encryption::{auth_encryption::AeKey, elgamal::ElGamalKeypair},
    js_sys::Uint8Array,
    solana_signature::Signature,
    solana_zk_sdk::encryption::derivation::{
        confidential_derivation_message, derive_confidential_keys_from_ikm,
        derive_confidential_keys_from_signature,
    },
    wasm_bindgen::prelude::{wasm_bindgen, JsValue},
};

/// Byte length of an ed25519 signature.
const SIGNATURE_LEN: usize = 64;

/// Accepted byte lengths for a WebAuthn PRF output: 32 bytes for a single
/// `prf.results.first` evaluation, 64 bytes for `first || second` concatenated.
const PRF_OUTPUT_LENS: [usize; 2] = [32, 64];

/// Container returned by the unified confidential-balances key derivation.
///
/// Both the ElGamal keypair and the AES (`decryptable_available_balance`
/// fast-path) key are derived from a single source of input key material
/// via a shared HKDF-SHA512 chain.
#[wasm_bindgen]
pub struct ConfidentialKeys {
    pub(crate) elgamal: ElGamalKeypair,
    pub(crate) ae: AeKey,
}

#[wasm_bindgen]
impl ConfidentialKeys {
    /// Returns the canonical derivation message a Solana signer must sign
    /// in order to deterministically derive a `ConfidentialKeys` pair via
    /// `fromSignature`.
    ///
    /// The message is `b"solana-conf-bal/v1" || public_seed`. `public_seed`
    /// is caller-controlled and granularity-agnostic; pass a wallet pubkey
    /// for per-wallet keying or a token-account pubkey for per-account
    /// keying.
    #[wasm_bindgen(js_name = "signerMessage")]
    pub fn signer_message(public_seed: Uint8Array) -> Vec<u8> {
        let mut seed = vec![0u8; public_seed.length() as usize];
        public_seed.copy_to(&mut seed);
        confidential_derivation_message(&seed)
    }

    /// Returns the canonical WebAuthn PRF evaluation input for `fromPrf`.
    ///
    /// Byte-identical to `signerMessage`: `b"solana-conf-bal/v1" || public_seed`.
    /// Pass it to the authenticator as the `prf.eval.first` salt. The same
    /// canonical message is signed in the Ed25519 path and PRF-evaluated in the
    /// passkey path, so a single seed convention drives both adapters.
    ///
    /// Browsers apply the mandatory `SHA-256("WebAuthn PRF" || 0x00 || input)`
    /// prefixing before the authenticator, so this message is passed as-is and
    /// may be any length. Non-browser / direct-CTAP `hmac-secret` consumers MUST
    /// reproduce that prefixing over this message to derive byte-identical keys.
    #[wasm_bindgen(js_name = "prfInput")]
    pub fn prf_input(public_seed: Uint8Array) -> Vec<u8> {
        let mut seed = vec![0u8; public_seed.length() as usize];
        public_seed.copy_to(&mut seed);
        confidential_derivation_message(&seed)
    }

    /// Derives a `ConfidentialKeys` pair from a 64-byte ed25519 signature
    /// over the message returned by `signerMessage`.
    #[wasm_bindgen(js_name = "fromSignature")]
    pub fn from_signature(signature: Uint8Array) -> Result<ConfidentialKeys, JsValue> {
        if signature.length() as usize != SIGNATURE_LEN {
            return Err(JsValue::from_str(&format!(
                "Invalid signature length: expected {}, got {}",
                SIGNATURE_LEN,
                signature.length()
            )));
        }
        let mut bytes = [0u8; SIGNATURE_LEN];
        signature.copy_to(&mut bytes);
        let signature = Signature::from(bytes);

        derive_confidential_keys_from_signature(&signature)
            .map(|(elgamal, ae)| Self {
                elgamal: elgamal.into(),
                ae: ae.into(),
            })
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Derives a `ConfidentialKeys` pair from raw input key material.
    ///
    /// Use this when the caller already produced 32 or more bytes of IKM
    /// via a non-`Signer` path: WebAuthn PRF output, Secure Enclave HMAC
    /// output, KMS `GenerateMac` output, HKDF over an Ed25519 seed, or a
    /// BIP39 seed.
    #[wasm_bindgen(js_name = "fromIkm")]
    pub fn from_ikm(ikm: Uint8Array) -> Result<ConfidentialKeys, JsValue> {
        let mut bytes = vec![0u8; ikm.length() as usize];
        ikm.copy_to(&mut bytes);

        derive_confidential_keys_from_ikm(&bytes)
            .map(|(elgamal, ae)| Self {
                elgamal: elgamal.into(),
                ae: ae.into(),
            })
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Derives a `ConfidentialKeys` pair from a WebAuthn PRF output (the
    /// passkey adapter).
    ///
    /// A passkey's ECDSA signing is randomized by spec, so signature-based
    /// derivation is structurally broken on passkey authenticators. The PRF
    /// (`hmac-secret`) extension is deterministic by construction and is the
    /// only viable path: evaluate `prf` over the salt returned by `prfInput`,
    /// then pass the result here.
    ///
    /// Accepts a 32-byte output (single `prf.results.first`) or a 64-byte
    /// output (`first || second` concatenated). The all-zero output is rejected
    /// as a non-functioning authenticator.
    #[wasm_bindgen(js_name = "fromPrf")]
    pub fn from_prf(prf_output: Uint8Array) -> Result<ConfidentialKeys, JsValue> {
        let len = prf_output.length() as usize;
        if !PRF_OUTPUT_LENS.contains(&len) {
            return Err(JsValue::from_str(&format!(
                "Invalid PRF output length: expected 32 or 64, got {len}"
            )));
        }
        let mut bytes = vec![0u8; len];
        prf_output.copy_to(&mut bytes);

        if bytes.iter().all(|&b| b == 0) {
            return Err(JsValue::from_str("Rejecting all-zero PRF output"));
        }

        derive_confidential_keys_from_ikm(&bytes)
            .map(|(elgamal, ae)| Self {
                elgamal: elgamal.into(),
                ae: ae.into(),
            })
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Returns the ElGamal keypair component.
    pub fn elgamal(&self) -> ElGamalKeypair {
        ElGamalKeypair {
            inner: self.elgamal.inner.clone(),
        }
    }

    /// Returns the AES key component.
    pub fn ae(&self) -> AeKey {
        AeKey {
            inner: self.ae.inner.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use {super::*, solana_zk_sdk::encryption::derivation::HKDF_SALT, wasm_bindgen_test::*};

    #[wasm_bindgen_test]
    fn test_signer_message_format() {
        let seed = [7u8; 32];
        let expected = [HKDF_SALT, seed.as_ref()].concat();
        let msg = ConfidentialKeys::signer_message(Uint8Array::from(seed.as_ref()));
        assert_eq!(msg, expected);
    }

    #[wasm_bindgen_test]
    fn test_signer_message_uses_unified_context() {
        // Sanity-check that the message uses the SRFC-aligned protocol
        // identifier rather than a per-key magic string.
        let seed = [0u8; 32];
        let msg = ConfidentialKeys::signer_message(Uint8Array::from(seed.as_ref()));
        assert!(msg.starts_with(b"solana-conf-bal/v1"));
        assert!(!msg.starts_with(b"AeKey"));
        assert!(!msg.starts_with(b"ElGamalSecretKey"));
    }

    #[wasm_bindgen_test]
    fn test_from_signature_determinism() {
        let signature_bytes = [3u8; 64];
        let sig = Uint8Array::from(signature_bytes.as_ref());

        let keys_a = ConfidentialKeys::from_signature(sig.clone()).unwrap();
        let keys_b = ConfidentialKeys::from_signature(sig).unwrap();
        assert_eq!(
            keys_a.elgamal().secret().to_bytes(),
            keys_b.elgamal().secret().to_bytes()
        );
        assert_eq!(keys_a.ae().to_bytes(), keys_b.ae().to_bytes());
    }

    #[wasm_bindgen_test]
    fn test_from_signature_rejects_wrong_length() {
        let short = vec![0u8; 63];
        assert!(ConfidentialKeys::from_signature(Uint8Array::from(short.as_slice())).is_err());
        let long = vec![0u8; 65];
        assert!(ConfidentialKeys::from_signature(Uint8Array::from(long.as_slice())).is_err());
    }

    #[wasm_bindgen_test]
    fn test_from_signature_rejects_default_signature() {
        let default = vec![0u8; 64];
        assert!(ConfidentialKeys::from_signature(Uint8Array::from(default.as_slice())).is_err());
    }

    #[wasm_bindgen_test]
    fn test_from_ikm_matches_from_signature_over_same_bytes() {
        let signature_bytes = [5u8; 64];
        let sig = Uint8Array::from(signature_bytes.as_ref());
        let ikm = Uint8Array::from(signature_bytes.as_ref());

        let from_sig = ConfidentialKeys::from_signature(sig).unwrap();
        let from_ikm = ConfidentialKeys::from_ikm(ikm).unwrap();

        assert_eq!(
            from_sig.elgamal().secret().to_bytes(),
            from_ikm.elgamal().secret().to_bytes()
        );
        assert_eq!(from_sig.ae().to_bytes(), from_ikm.ae().to_bytes());
    }

    #[wasm_bindgen_test]
    fn test_from_ikm_rejects_short() {
        let too_short = vec![0u8; 31];
        assert!(ConfidentialKeys::from_ikm(Uint8Array::from(too_short.as_slice())).is_err());
    }

    #[wasm_bindgen_test]
    fn test_prf_input_matches_signer_message() {
        // The passkey PRF input is the same canonical message as the Ed25519
        // signing path, so a single seed convention drives both adapters.
        let seed = [9u8; 32];
        let prf = ConfidentialKeys::prf_input(Uint8Array::from(seed.as_ref()));
        let signer = ConfidentialKeys::signer_message(Uint8Array::from(seed.as_ref()));
        assert_eq!(prf, signer);
        assert!(prf.starts_with(b"solana-conf-bal/v1"));
    }

    #[wasm_bindgen_test]
    fn test_from_prf_determinism() {
        let prf_output = [3u8; 32];
        let out = Uint8Array::from(prf_output.as_ref());

        let keys_a = ConfidentialKeys::from_prf(out.clone()).unwrap();
        let keys_b = ConfidentialKeys::from_prf(out).unwrap();
        assert_eq!(
            keys_a.elgamal().secret().to_bytes(),
            keys_b.elgamal().secret().to_bytes()
        );
        assert_eq!(keys_a.ae().to_bytes(), keys_b.ae().to_bytes());
    }

    #[wasm_bindgen_test]
    fn test_from_prf_matches_from_ikm_over_same_bytes() {
        // A PRF output is just IKM into the shared spine, so `fromPrf` and
        // `fromIkm` over identical bytes must agree.
        let prf_output = [5u8; 32];
        let from_prf = ConfidentialKeys::from_prf(Uint8Array::from(prf_output.as_ref())).unwrap();
        let from_ikm = ConfidentialKeys::from_ikm(Uint8Array::from(prf_output.as_ref())).unwrap();

        assert_eq!(
            from_prf.elgamal().secret().to_bytes(),
            from_ikm.elgamal().secret().to_bytes()
        );
        assert_eq!(from_prf.ae().to_bytes(), from_ikm.ae().to_bytes());
    }

    #[wasm_bindgen_test]
    fn test_from_prf_accepts_64_byte_output() {
        // `first || second` concatenation is a valid 64-byte PRF output.
        let prf_output = [7u8; 64];
        assert!(ConfidentialKeys::from_prf(Uint8Array::from(prf_output.as_ref())).is_ok());
    }

    #[wasm_bindgen_test]
    fn test_from_prf_rejects_wrong_length() {
        for len in [31usize, 33, 48, 63, 65] {
            let bad = vec![1u8; len];
            assert!(
                ConfidentialKeys::from_prf(Uint8Array::from(bad.as_slice())).is_err(),
                "length {len} should be rejected"
            );
        }
    }

    #[wasm_bindgen_test]
    fn test_from_prf_rejects_all_zero() {
        let zero_32 = vec![0u8; 32];
        assert!(ConfidentialKeys::from_prf(Uint8Array::from(zero_32.as_slice())).is_err());
        let zero_64 = vec![0u8; 64];
        assert!(ConfidentialKeys::from_prf(Uint8Array::from(zero_64.as_slice())).is_err());
    }
}
