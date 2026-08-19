import assert from "assert";
// The root export: no build hardcoded, resolved by condition.
import { PubkeyValidityProofData, ElGamalKeypair } from "@solana/zk-sdk";
// The bundler subpath, which packages such as `@solana-program/token-2022`
// import directly. Under the `node` condition it must serve the Node build,
// or it fails to load (`ERR_UNKNOWN_FILE_EXTENSION` on the `.wasm`).
import { ElGamalKeypair as BundlerElGamalKeypair } from "@solana/zk-sdk/bundler";

console.log("--- Running Node.js (ESM) integration tests ---");

try {
  const keypair = new ElGamalKeypair();
  assert.ok(keypair, "Keypair creation failed");

  const proof = new PubkeyValidityProofData(keypair);
  assert.ok(proof, "Proof creation failed");

  proof.verify();

  // Both specifiers must resolve to the same build, so the WASM module is
  // instantiated once and class identities match across them. A second
  // instance shows up as `expected instance of ElGamalKeypair` when a keypair
  // from one is passed to the other.
  assert.strictEqual(
    ElGamalKeypair,
    BundlerElGamalKeypair,
    "Root and bundler imports resolved to different WASM instances",
  );

  const bundlerKeypair = new BundlerElGamalKeypair();
  new PubkeyValidityProofData(bundlerKeypair).verify();

  console.log("✅ Node.js (ESM) integration tests passed!");
} catch (error) {
  console.error("❌ Node.js (ESM) integration tests failed:", error);
  process.exit(1);
}
