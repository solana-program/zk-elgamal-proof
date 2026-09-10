use {
    crate::encryption::{auth_encryption::AeKey, elgamal::ElGamalKeypair},
    js_sys::Uint8Array,
    solana_signature::Signature,
    solana_zk_sdk::encryption::derivation::{
        confidential_derivation_message, derive_confidential_keys_from_ikm,
        derive_confidential_keys_from_signature,
        pda_wallet_public_seed as sdk_pda_wallet_public_seed, PDA_WALLET_PUBLIC_SEED_FIELD_LEN,
        STANDARD_DERIVATION_MESSAGE,
    },
    wasm_bindgen::prelude::{wasm_bindgen, JsValue},
};

/// Byte length of an ed25519 signature.
const SIGNATURE_LEN: usize = 64;

/// Accepted byte lengths for a WebAuthn PRF output: 32 bytes for a single
/// `prf.results.first` evaluation, 64 bytes for `first || second` concatenated.
const PRF_OUTPUT_LENS: [usize; 2] = [32, 64];

fn copy_public_seed_field(
    name: &str,
    field: &Uint8Array,
) -> Result<[u8; PDA_WALLET_PUBLIC_SEED_FIELD_LEN], JsValue> {
    if field.length() as usize != PDA_WALLET_PUBLIC_SEED_FIELD_LEN {
        return Err(JsValue::from_str(&format!(
            "Invalid {name} length: expected {}, got {}",
            PDA_WALLET_PUBLIC_SEED_FIELD_LEN,
            field.length()
        )));
    }

    let mut bytes = [0u8; PDA_WALLET_PUBLIC_SEED_FIELD_LEN];
    field.copy_to(&mut bytes);
    Ok(bytes)
}

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
    /// Returns the standard derivation message: the constant bytes
    /// `solana-conf-bal/v1` a Solana wallet signs once to derive its
    /// `ConfidentialKeys` pair via `fromSignature`.
    ///
    /// The derived keys are bound to the signing wallet alone (one ElGamal
    /// keypair and one AES key across all of the wallet's mints and token
    /// accounts) and match what every other standard client derives for the
    /// same wallet.
    ///
    /// Wallets SHOULD recognize these exact bytes, expose the signature only
    /// through a dedicated key-derivation API, and refuse any generic
    /// `signMessage` request whose message starts with this prefix: the
    /// resulting signature is the input key material for the wallet's
    /// confidential-balance decryption keys.
    ///
    /// Takes no arguments; passing one throws. JavaScript otherwise drops
    /// extra arguments silently, so a caller on the pre-rename seeded
    /// convention would derive different keys than intended without noticing.
    #[wasm_bindgen(js_name = "signerMessage")]
    pub fn signer_message(unexpected_seed: Option<Uint8Array>) -> Result<Vec<u8>, JsValue> {
        if unexpected_seed.is_some() {
            return Err(JsValue::from_str(
                "signerMessage takes no arguments; for seed-scoped (non-standard) derivation use signerMessageWithSeed",
            ));
        }
        Ok(STANDARD_DERIVATION_MESSAGE.to_vec())
    }

    /// Returns the non-standard, seed-scoped derivation message:
    /// `b"solana-conf-bal/v1" || public_seed`.
    ///
    /// Use this only for schemes that genuinely need keys scoped more finely
    /// than the wallet (single-signer PDA wallets via `pdaWalletPublicSeed`,
    /// custom application keying). Keys derived from a non-empty seed will NOT
    /// match the standard keys other clients derive for the same wallet; for
    /// standard wallet-level keys use `signerMessage`.
    #[wasm_bindgen(js_name = "signerMessageWithSeed")]
    pub fn signer_message_with_seed(public_seed: Uint8Array) -> Vec<u8> {
        confidential_derivation_message(&public_seed.to_vec())
    }

    /// Returns the standard WebAuthn PRF evaluation input for `fromPrf`:
    /// byte-identical to `signerMessage` (the constant `solana-conf-bal/v1`).
    ///
    /// Pass it to the authenticator as the `prf.eval.first` salt. The same
    /// canonical message is signed in the Ed25519 path and PRF-evaluated in the
    /// passkey path, so both adapters derive wallet-level keys by default.
    ///
    /// Browsers apply the mandatory `SHA-256("WebAuthn PRF" || 0x00 || input)`
    /// prefixing before the authenticator, so this message is passed as-is.
    /// Non-browser / direct-CTAP `hmac-secret` consumers MUST reproduce that
    /// prefixing over this message to derive byte-identical keys.
    ///
    /// Takes no arguments; passing one throws (see `signerMessage`). For
    /// seed-scoped PRF input use `prfInputWithSeed`.
    #[wasm_bindgen(js_name = "prfInput")]
    pub fn prf_input(unexpected_seed: Option<Uint8Array>) -> Result<Vec<u8>, JsValue> {
        if unexpected_seed.is_some() {
            return Err(JsValue::from_str(
                "prfInput takes no arguments; for seed-scoped (non-standard) derivation use prfInputWithSeed",
            ));
        }
        Ok(STANDARD_DERIVATION_MESSAGE.to_vec())
    }

    /// Returns the non-standard, seed-scoped WebAuthn PRF evaluation input:
    /// byte-identical to `signerMessageWithSeed`. See `signerMessageWithSeed`
    /// for when a seed is appropriate; see `prfInput` for the standard path.
    #[wasm_bindgen(js_name = "prfInputWithSeed")]
    pub fn prf_input_with_seed(public_seed: Uint8Array) -> Vec<u8> {
        confidential_derivation_message(&public_seed.to_vec())
    }

    /// Returns the canonical `public_seed` for single-signer PDA wallet accounts.
    ///
    /// The output is `program_id || wallet_pda || mint || token_account`.
    /// Pass it to `signerMessageWithSeed` or `prfInputWithSeed` so PDA/passkey
    /// wallets use a consistent seed convention across implementations.
    #[wasm_bindgen(js_name = "pdaWalletPublicSeed")]
    pub fn pda_wallet_public_seed(
        program_id: Uint8Array,
        wallet_pda: Uint8Array,
        mint: Uint8Array,
        token_account: Uint8Array,
    ) -> Result<Vec<u8>, JsValue> {
        let program_id = copy_public_seed_field("program_id", &program_id)?;
        let wallet_pda = copy_public_seed_field("wallet_pda", &wallet_pda)?;
        let mint = copy_public_seed_field("mint", &mint)?;
        let token_account = copy_public_seed_field("token_account", &token_account)?;

        Ok(sdk_pda_wallet_public_seed(&program_id, &wallet_pda, &mint, &token_account).to_vec())
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
    /// then pass the result here as a `Uint8Array`. The browser exposes
    /// `prf.results.first` as a raw `ArrayBuffer`, so wrap it with
    /// `new Uint8Array(result)` before calling.
    ///
    /// Accepts a 32-byte output (single `prf.results.first`) or a 64-byte
    /// output (`first || second` concatenated). The all-zero output is rejected
    /// as a non-functioning authenticator.
    #[wasm_bindgen(js_name = "fromPrf")]
    pub fn from_prf(prf_output: Uint8Array) -> Result<ConfidentialKeys, JsValue> {
        let bytes = prf_output.to_vec();
        if !PRF_OUTPUT_LENS.contains(&bytes.len()) {
            return Err(JsValue::from_str(&format!(
                "Invalid PRF output length: expected 32 or 64, got {}",
                bytes.len()
            )));
        }

        let is_all_zero = bytes.iter().fold(0u8, |acc, &b| acc | b) == 0;
        if is_all_zero {
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
    fn test_signer_message_is_standard_constant() {
        // The standard message is the bare protocol identifier: what a wallet
        // signs once to derive its wallet-level keys, and the exact prefix
        // wallets should refuse through generic signMessage.
        let msg = ConfidentialKeys::signer_message(None).unwrap();
        assert_eq!(msg, b"solana-conf-bal/v1");
        assert_eq!(
            msg,
            ConfidentialKeys::signer_message_with_seed(Uint8Array::from([].as_ref()))
        );
    }

    #[wasm_bindgen_test]
    fn test_standard_messages_reject_a_seed_argument() {
        // JavaScript drops extra arguments silently, so the pre-rename seeded
        // calling convention must fail loudly instead of deriving the
        // standard keys.
        let seed = Uint8Array::from([7u8; 32].as_ref());
        assert!(ConfidentialKeys::signer_message(Some(seed.clone())).is_err());
        assert!(ConfidentialKeys::prf_input(Some(seed)).is_err());
    }

    #[wasm_bindgen_test]
    fn test_signer_message_with_seed_format() {
        let seed = [7u8; 32];
        let expected = [HKDF_SALT, seed.as_ref()].concat();
        let msg = ConfidentialKeys::signer_message_with_seed(Uint8Array::from(seed.as_ref()));
        assert_eq!(msg, expected);
    }

    #[wasm_bindgen_test]
    fn test_signer_message_uses_unified_context() {
        // Sanity-check that the message uses the SRFC-aligned protocol
        // identifier rather than a per-key magic string.
        let seed = [0u8; 32];
        let msg = ConfidentialKeys::signer_message_with_seed(Uint8Array::from(seed.as_ref()));
        assert!(msg.starts_with(b"solana-conf-bal/v1"));
        assert!(!msg.starts_with(b"AeKey"));
        assert!(!msg.starts_with(b"ElGamalSecretKey"));
    }

    #[wasm_bindgen_test]
    fn test_from_signature_standard_vector() {
        // Canonical cross-SDK vector for the standard (wallet-level) path.
        // The signature is ed25519_sign(seed = 0x1122...ff00 twice, message =
        // signerMessage()); the expected keys are pinned identically in the
        // zk-sdk Rust tests, the solana-go fixtures (keypair_a_empty_seed),
        // and the Token-2022 JS client tests.
        let signature: [u8; 64] = [
            0x61, 0xdd, 0xf9, 0x56, 0xab, 0xdf, 0xb6, 0xe0, 0xc4, 0x4a, 0x3b, 0x81, 0x6f, 0x4b,
            0x8d, 0xd4, 0x22, 0xbd, 0x99, 0x54, 0xaa, 0xea, 0x4d, 0xb4, 0xab, 0x6c, 0x5e, 0xf0,
            0x7a, 0x61, 0x86, 0x1f, 0xa4, 0xd0, 0x28, 0xc8, 0x5d, 0x46, 0x3e, 0x6e, 0x95, 0xcb,
            0xc9, 0xb9, 0xa5, 0xa3, 0xf5, 0x1f, 0x27, 0x2e, 0xab, 0x0f, 0x54, 0xf9, 0x1e, 0xda,
            0x15, 0x93, 0x63, 0x8d, 0x25, 0xc5, 0xe8, 0x0b,
        ];
        let expected_ae: [u8; 16] = [
            0x64, 0x17, 0xee, 0xdb, 0xcb, 0xe9, 0xc6, 0x4a, 0x72, 0x39, 0x57, 0x19, 0xec, 0x98,
            0xcf, 0x6b,
        ];
        let expected_elgamal: [u8; 32] = [
            0xbe, 0x5c, 0xce, 0x95, 0x1f, 0x42, 0xa2, 0xa8, 0x67, 0x7d, 0x1a, 0x56, 0xf0, 0x3a,
            0xae, 0x7b, 0xff, 0x79, 0x5b, 0x38, 0xcf, 0x1c, 0x56, 0xc8, 0xcf, 0x3a, 0x4d, 0xae,
            0x7d, 0x60, 0xe2, 0x05,
        ];

        let keys = ConfidentialKeys::from_signature(Uint8Array::from(signature.as_ref())).unwrap();
        assert_eq!(keys.ae().to_bytes(), expected_ae);
        assert_eq!(keys.elgamal().secret().to_bytes(), expected_elgamal);
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
        // signing path, in both the standard and the seeded variants.
        assert_eq!(
            ConfidentialKeys::prf_input(None).unwrap(),
            ConfidentialKeys::signer_message(None).unwrap()
        );

        let seed = [9u8; 32];
        let prf = ConfidentialKeys::prf_input_with_seed(Uint8Array::from(seed.as_ref()));
        let signer = ConfidentialKeys::signer_message_with_seed(Uint8Array::from(seed.as_ref()));
        assert_eq!(prf, signer);
        assert!(prf.starts_with(b"solana-conf-bal/v1"));
    }

    #[wasm_bindgen_test]
    fn test_pda_wallet_public_seed_format() {
        let seed = ConfidentialKeys::pda_wallet_public_seed(
            Uint8Array::from([0x11u8; 32].as_ref()),
            Uint8Array::from([0x22u8; 32].as_ref()),
            Uint8Array::from([0x33u8; 32].as_ref()),
            Uint8Array::from([0x44u8; 32].as_ref()),
        )
        .unwrap();

        assert_eq!(seed.len(), 128);
        assert_eq!(&seed[0..32], [0x11u8; 32].as_ref());
        assert_eq!(&seed[32..64], [0x22u8; 32].as_ref());
        assert_eq!(&seed[64..96], [0x33u8; 32].as_ref());
        assert_eq!(&seed[96..128], [0x44u8; 32].as_ref());
    }

    #[wasm_bindgen_test]
    fn test_pda_wallet_public_seed_rejects_wrong_length() {
        let good = Uint8Array::from([0x11u8; 32].as_ref());
        let bad = Uint8Array::from([0x22u8; 31].as_ref());

        assert!(ConfidentialKeys::pda_wallet_public_seed(
            bad.clone(),
            good.clone(),
            good.clone(),
            good.clone(),
        )
        .is_err());
        assert!(ConfidentialKeys::pda_wallet_public_seed(
            good.clone(),
            bad.clone(),
            good.clone(),
            good.clone(),
        )
        .is_err());
        assert!(ConfidentialKeys::pda_wallet_public_seed(
            good.clone(),
            good.clone(),
            bad.clone(),
            good.clone(),
        )
        .is_err());
        assert!(
            ConfidentialKeys::pda_wallet_public_seed(good.clone(), good.clone(), good, bad,)
                .is_err()
        );
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
