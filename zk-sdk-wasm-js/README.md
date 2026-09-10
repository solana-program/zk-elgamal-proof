# `@solana/zk-sdk`

WebAssembly bindings for the Rust [`solana-zk-sdk`](https://github.com/solana-program/zk-elgamal-proof/tree/main/zk-sdk). Use it from Node, the browser, or a bundler to generate the zero-knowledge proofs used by the Token-2022 confidential-balances extension, and to derive the ElGamal and AES keys those balances are encrypted under.

## Install

```sh
npm install @solana/zk-sdk
```

The package ships three builds, one per `wasm-pack` target. Import the package root and the right one is selected for you; the subpaths are there when you need to pin a build explicitly:

| Import | Target | Init |
|---|---|---|
| `@solana/zk-sdk` | Node and bundlers — `node` gets the Node build, browser bundlers get the bundler build | none, ready on import |
| `@solana/zk-sdk/node` | Node.js | none, ready on import |
| `@solana/zk-sdk/web` | browser, no bundler | call the default `init()` once before use |
| `@solana/zk-sdk/bundler` | Vite / webpack / etc. | none, the bundler loads the wasm |

```js
// Node or a bundler
import { ConfidentialKeys } from "@solana/zk-sdk";

// Browser without a bundler
import init, { ConfidentialKeys } from "@solana/zk-sdk/web";
await init();
```

The `web` build is the one case the root export cannot pick for you: it needs an explicit `init()`, so import it by subpath. `@solana/zk-sdk/bundler` also resolves to the Node build under the `node` condition — the ESM bundler build cannot load its `.wasm` outside a bundler, so a Node runtime (including the server side of a bundled app) is always served the Node build.

## Confidential-balances key derivation

A confidential token account is encrypted under two keys: an **ElGamal keypair** (the balance ciphertext) and an **AES key** (the `decryptable_available_balance` fast-path). `ConfidentialKeys` derives both deterministically from a single source of key material, through a shared HKDF-SHA512 chain identified by the protocol string `solana-conf-bal/v1`. Re-deriving from the same input always yields the same keys, on any platform that implements the same chain.

There is one entry point per source of key material. Pick the one that matches how your wallet holds its secret:

| Source | Method | Notes |
|---|---|---|
| WebAuthn passkey | `prfInput` + `fromPrf` | the only viable path for passkeys |
| Ed25519 wallet signature | `signerMessage` + `fromSignature` | today's universal wallet path |
| Raw input key material | `fromIkm` | Secure Enclave / KMS HMAC, BIP39 seed, etc. |

All three converge on the same spine, so `fromSignature(sig)`, `fromIkm(bytes)`, and `fromPrf(out)` over the same input bytes produce identical keys. In practice different adapters never produce the same input bytes for the same wallet; see the interchangeability note under The standard message.

```js
const keys = ConfidentialKeys.fromPrf(prfOutput);
const elgamal = keys.elgamal(); // ElGamalKeypair
const ae = keys.ae();           // AeKey
```

### The standard message

`signerMessage()` and `prfInput()` take no arguments (passing one throws) and return the constant standard message, the bytes `solana-conf-bal/v1`. The derived keys are bound to the wallet alone: one key pair covering all of the wallet's confidential accounts. There is nothing to configure, which is the point: every standard client derives the same message because none of them can pass a different seed by accident.

The cross-SDK guarantee (byte-identical keys to the Token-2022 clients, the Rust and Go SDKs, and the confidential-transfer docs) applies to the canonical deterministic Ed25519 signing path: the same wallet key signing the same constant message. The adapters are not interchangeable with each other: a WebAuthn PRF evaluation and an Ed25519 signature over the same message produce different input key material and therefore different keys, and PRF/raw-IKM keys are reproducible only while the same credential or key material is used. Pick one adapter per account at provisioning and keep it.

Wallets SHOULD refuse to sign any message starting with `solana-conf-bal/v1` through generic `signMessage` and expose the derivation signature only via a dedicated key-derivation capability: a signature over the derivation message is equivalent to handing out the account's decryption keys.

### Non-standard seed scoping

`signerMessageWithSeed(seed)` and `prfInputWithSeed(seed)` build `solana-conf-bal/v1 || seed` for schemes that genuinely need keys scoped more finely than the wallet. Keys derived from a non-empty seed will not match the standard keys other clients derive for the same wallet. For single-signer PDA wallets specifically, use `pdaWalletPublicSeed` to bind the derived keys to the wallet program, wallet PDA, mint, and concrete token account:

```js
const publicSeed = ConfidentialKeys.pdaWalletPublicSeed(
  programId.toBytes(),
  walletPda.toBytes(),
  mint.toBytes(),
  tokenAccount.toBytes(),
);
const message = ConfidentialKeys.signerMessageWithSeed(publicSeed);
```

### Passkeys (WebAuthn PRF)

Passkey ECDSA signing is randomized by spec, so signature-based derivation is impossible on passkey authenticators. The PRF (`hmac-secret`) extension is deterministic by construction and is the only path. PRF must be enabled when the credential is **registered**; legacy credentials that predate it cannot be used.

```js
import { ConfidentialKeys } from "@solana/zk-sdk";

// 1. One-time, at credential registration (pure WebAuthn, not this SDK).
//    Enabling PRF here is mandatory.
const cred = await navigator.credentials.create({
  publicKey: { /* rp, user, challenge, pubKeyCredParams */, extensions: { prf: {} } },
});
const credentialId = new Uint8Array(cred.rawId);

// 2. Per session: evaluate the PRF over the standard input, then derive.
const salt = ConfidentialKeys.prfInput();

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

`prfInput` returns the standard message `solana-conf-bal/v1`, byte-identical to `signerMessage` (`prfInputWithSeed` mirrors `signerMessageWithSeed` for non-standard scoping). It is passed to `prf.eval.first` as-is: browsers apply the mandatory `SHA-256("WebAuthn PRF" || 0x00 || input)` prefixing before the authenticator, so the input must not be pre-hashed. A non-browser or direct-CTAP `hmac-secret` consumer must reproduce that prefixing over this message to derive matching keys.

### Ed25519 wallet signature

For a normal Solana wallet, derive from a single deterministic Ed25519 signature over the standard message.

```js
import { ConfidentialKeys } from "@solana/zk-sdk";

const message = ConfidentialKeys.signerMessage();      // constant: "solana-conf-bal/v1"
const signature = await wallet.signMessage(message);   // 64-byte Ed25519 signature
const keys = ConfidentialKeys.fromSignature(signature);
```

`wallet.signMessage` here stands for however the integration obtains the derivation signature. A wallet that implements the refusal recommendation above exposes this signature through a dedicated key-derivation capability rather than its generic `signMessage`; a filesystem or server-side signer signs the raw bytes directly. Reproducible derivation additionally requires the signer to be deterministic (RFC 8032) over these exact bytes: a randomized Ed25519 implementation returns a different valid signature each call and therefore different keys.

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
