import assert from "assert";

console.log("--- Running Node.js (ESM) integration tests ---");

try {
  // Dynamic imports, so a resolution failure lands in the catch below with a
  // readable message instead of an uncaught `ERR_*` before this file runs.

  // The root export: no build hardcoded, resolved by condition.
  const { PubkeyValidityProofData, ElGamalKeypair } =
    await import("@solana/zk-sdk");
  // The bundler subpath, which packages such as `@solana-program/token-2022`
  // import directly. Under the `node` condition it must serve the Node build,
  // or it fails to load (`ERR_UNKNOWN_FILE_EXTENSION` on the `.wasm`).
  const { ElGamalKeypair: BundlerElGamalKeypair } =
    await import("@solana/zk-sdk/bundler");
  // The Node subpath, which an app may pin explicitly while a dependency still
  // imports `/bundler` — the mixed case that happens in practice.
  const { ElGamalKeypair: NodeElGamalKeypair } =
    await import("@solana/zk-sdk/node");

  const keypair = new ElGamalKeypair();
  assert.ok(keypair, "Keypair creation failed");

  const proof = new PubkeyValidityProofData(keypair);
  assert.ok(proof, "Proof creation failed");

  proof.verify();

  // All three specifiers must resolve to the same build, so the WASM module is
  // instantiated once and class identities match across them. A second
  // instance shows up as `expected instance of ElGamalKeypair` when a keypair
  // from one is passed to the other.
  assert.strictEqual(
    ElGamalKeypair,
    BundlerElGamalKeypair,
    "Root and bundler imports resolved to different WASM instances",
  );
  assert.strictEqual(
    ElGamalKeypair,
    NodeElGamalKeypair,
    "Root and node imports resolved to different WASM instances",
  );

  const bundlerKeypair = new BundlerElGamalKeypair();
  new PubkeyValidityProofData(bundlerKeypair).verify();

  const nodeKeypair = new NodeElGamalKeypair();
  new PubkeyValidityProofData(nodeKeypair).verify();

  console.log("✅ Node.js (ESM) integration tests passed!");
} catch (error) {
  console.error("❌ Node.js (ESM) integration tests failed:", error);
  process.exit(1);
}
