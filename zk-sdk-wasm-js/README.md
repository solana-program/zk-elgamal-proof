# `@solana/zk-sdk`

WebAssembly bindings for the Rust [`solana-zk-sdk`](https://github.com/solana-program/zk-elgamal-proof/tree/main/zk-sdk). Use it from Node, the browser, or a bundler to generate the zero-knowledge proofs used by the Token-2022 confidential-balances extension, and to derive the ElGamal and AES keys those balances are encrypted under.

## Install

```sh
npm install @solana/zk-sdk
```

The package ships three builds, one per `wasm-pack` target:

| Import | Target | Init |
|---|---|---|
| `@solana/zk-sdk/node` | Node.js | none, ready on import |
| `@solana/zk-sdk/web` | browser, no bundler | call the default `init()` once before use |
| `@solana/zk-sdk/bundler` | Vite / webpack / etc. (package default) | none, the bundler loads the wasm |

```js
// Node
import { ConfidentialKeys } from "@solana/zk-sdk/node";

// Bundler (Vite, webpack)
import { ConfidentialKeys } from "@solana/zk-sdk/bundler";

// Browser without a bundler
import init, { ConfidentialKeys } from "@solana/zk-sdk/web";
await init();
```

## Confidential-balances key derivation

A confidential token account is encrypted under two keys: an **ElGamal keypair** (the balance ciphertext) and an **AES key** (the `decryptable_available_balance` fast-path). `ConfidentialKeys` derives both deterministically from a single source of key material, through a shared HKDF-SHA512 chain identified by the protocol string `solana-conf-bal/v1`. Re-deriving from the same input always yields the same keys, on any platform that implements the same chain.

There is one entry point per source of key material. Pick the one that matches how your wallet holds its secret:

| Source | Method | Notes |
|---|---|---|
| WebAuthn passkey | `prfInput` + `fromPrf` | the only viable path for passkeys |
| Ed25519 wallet signature | `signerMessage` + `fromSignature` | today's universal wallet path |
| Raw input key material | `fromIkm` | Secure Enclave / KMS HMAC, BIP39 seed, etc. |

All three converge on the same spine, so `fromSignature(sig)`, `fromIkm(bytes)`, and `fromPrf(out)` over the same bytes produce identical keys.

```js
const keys = ConfidentialKeys.fromPrf(prfOutput);
const elgamal = keys.elgamal(); // ElGamalKeypair
const ae = keys.ae();           // AeKey
```

### The `public_seed`

`signerMessage` and `prfInput` both take a caller-chosen `public_seed` that scopes the derivation. It is granularity-agnostic: pass a token-account pubkey for per-account keys, or a wallet pubkey for one key across all of a wallet's accounts. The SDK does not enforce a convention, but two wallets must agree on it (and on which adapter they use) to derive the same keys for the same account.

For single-signer PDA wallets, use `pdaWalletPublicSeed` to bind the derived keys to the wallet program, wallet PDA, mint, and concrete token account:

```js
const publicSeed = ConfidentialKeys.pdaWalletPublicSeed(
  programId.toBytes(),
  walletPda.toBytes(),
  mint.toBytes(),
  tokenAccount.toBytes(),
);
```

### Passkeys (WebAuthn PRF)

Passkey ECDSA signing is randomized by spec, so signature-based derivation is impossible on passkey authenticators. The PRF (`hmac-secret`) extension is deterministic by construction and is the only path. PRF must be enabled when the credential is **registered**; legacy credentials that predate it cannot be used.

```js
import { ConfidentialKeys } from "@solana/zk-sdk/bundler";

// 1. One-time, at credential registration (pure WebAuthn, not this SDK).
//    Enabling PRF here is mandatory.
const cred = await navigator.credentials.create({
  publicKey: { /* rp, user, challenge, pubKeyCredParams */, extensions: { prf: {} } },
});
const credentialId = new Uint8Array(cred.rawId);

// 2. Per session: evaluate the PRF over our canonical input, then derive.
const publicSeed = tokenAccount.toBytes();           // your granularity choice
const salt = ConfidentialKeys.prfInput(publicSeed);

const assertion = await navigator.credentials.get({
  publicKey: {
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    allowCredentials: [{ id: credentialId, type: "public-key" }],
    extensions: { prf: { eval: { first: salt } } },
  },
});

const prf = assertion.getClientExtensionResults().prf?.results?.first;
if (!prf) throw new Error("authenticator returned no PRF result");

const keys = ConfidentialKeys.fromPrf(new Uint8Array(prf));
```

`fromPrf` accepts a 32-byte output (a single `prf.results.first`) or a 64-byte output (`first || second` concatenated), and rejects an all-zero result.

`prfInput` returns the canonical message `solana-conf-bal/v1 || public_seed`, byte-identical to `signerMessage`. It is passed to `prf.eval.first` as-is: browsers apply the mandatory `SHA-256("WebAuthn PRF" || 0x00 || input)` prefixing before the authenticator, so the input length is unconstrained and must not be pre-hashed. A non-browser or direct-CTAP `hmac-secret` consumer must reproduce that prefixing over this message to derive matching keys.

### Ed25519 wallet signature

For a normal Solana wallet, derive from a single `signMessage` over the canonical message.

```js
import { ConfidentialKeys } from "@solana/zk-sdk/web";

const message = ConfidentialKeys.signerMessage(tokenAccount.toBytes());
const signature = await wallet.signMessage(message);   // 64-byte Ed25519 signature
const keys = ConfidentialKeys.fromSignature(signature);
```

The all-zero (default) signature is rejected: some signers return it instead of raising an error, and the resulting keys would be predictable.

### Raw input key material

When the wallet exposes an HMAC/HKDF primitive directly (iOS Secure Enclave, AWS KMS `GenerateMac`, a BIP39 seed, HKDF over an Ed25519 seed), pass that output straight in.

```js
const keys = ConfidentialKeys.fromIkm(ikm); // 32 to 65535 bytes
```

## Things to get right

- **Identity bindings are forever.** WebAuthn PRF output is bound to the Relying Party ID; the signature path is bound to the signing key; raw IKM is bound to its source. Change the binding and the old balance can no longer be decrypted. Commit to a stable RP ID at provisioning and never change it.
- **Cache the derived keys for the session.** Do not re-prompt for a signature or device unlock per transfer. Derive once, hold the keys in memory, wipe on background.
- **Back up device-bound keys.** Deterministic derivation does not survive device or credential loss. Passkey and Secure Enclave wallets need an explicit recovery path (synced credentials or wrapped-key escrow).

## Background

The derivation scheme and the per-wallet adapter typology are described in the Solana confidential-balances single-signer derivation framework. The Rust spine and its test vectors live in [`zk-sdk/src/encryption/derivation.rs`](https://github.com/solana-program/zk-elgamal-proof/blob/main/zk-sdk/src/encryption/derivation.rs).
