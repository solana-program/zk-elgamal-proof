const assert = require("assert");
const {
  PubkeyValidityProofData,
  ElGamalKeypair,
  PedersenOpening,
} = require("@solana/zk-sdk/node");

console.log("--- Running Node.js (CJS) integration tests ---");

try {
  const keypair = new ElGamalKeypair();
  assert.ok(keypair, "Keypair creation failed");

  const proof = new PubkeyValidityProofData(keypair);
  assert.ok(proof, "Proof creation failed");

  proof.verify();

  const pubkey = keypair.pubkey();
  const secret = keypair.secret();
  const ciphertext = pubkey.encryptU64(55n);
  const other = pubkey.encryptU64(13n);
  assert.strictEqual(secret.decrypt(ciphertext.add(other)), 68n);
  assert.strictEqual(secret.decrypt(ciphertext.subtract(other)), 42n);
  assert.strictEqual(secret.decrypt(other.multiplyByU64(6n)), 78n);
  assert.strictEqual(secret.decrypt(ciphertext.addAmount(13n)), 68n);
  assert.strictEqual(secret.decrypt(ciphertext.subtractAmount(13n)), 42n);

  // Exercise the full u64 range through the JavaScript bigint bindings.
  const maxU64 = (1n << 64n) - 1n;
  const opening = new PedersenOpening();
  const zero = pubkey.encryptWith(0n, opening);
  const one = pubkey.encryptWith(1n, opening);
  const max = pubkey.encryptWith(maxU64, opening);
  assert.deepStrictEqual(zero.addAmount(maxU64).toBytes(), max.toBytes());
  assert.deepStrictEqual(max.subtractAmount(maxU64).toBytes(), zero.toBytes());
  assert.deepStrictEqual(
    one.multiplyByU64(maxU64).toBytes(),
    pubkey.encryptWith(maxU64, opening.multiplyByU64(maxU64)).toBytes(),
  );

  console.log("✅ Node.js integration tests passed!");
} catch (error) {
  console.error("❌ Node.js integration tests failed:", error);
  process.exit(1);
}
