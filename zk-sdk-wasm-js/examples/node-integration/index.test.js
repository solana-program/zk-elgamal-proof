const assert = require("assert");
const {
  PubkeyValidityProofData,
  ElGamalKeypair,
} = require("@solana/zk-sdk/node");

console.log("--- Running Node.js (CJS) integration tests ---");

try {
  const keypair = new ElGamalKeypair();
  assert.ok(keypair, "Keypair creation failed");

  const proof = new PubkeyValidityProofData(keypair);
  assert.ok(proof, "Proof creation failed");

  proof.verify();

  console.log("✅ Node.js integration tests passed!");
} catch (error) {
  console.error("❌ Node.js integration tests failed:", error);
  process.exit(1);
}
