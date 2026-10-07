const assert = require("assert");
const {
  PubkeyValidityProofData,
  ElGamalCiphertext,
  ElGamalKeypair,
  GroupedElGamalCiphertext2Handles,
  GroupedElGamalCiphertext3Handles,
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

  const hiOpening = new PedersenOpening();
  const hi = pubkey.encryptWith(2n, hiOpening);
  assert.deepStrictEqual(
    ElGamalCiphertext.combineLoHi(one, hi, 16).toBytes(),
    pubkey
      .encryptWith(1n + (2n << 16n), PedersenOpening.combineLoHi(opening, hiOpening, 16))
      .toBytes(),
  );
  assert.throws(
    () => ElGamalCiphertext.combineLoHi(one, hi, 64),
    /bit length must be less than 64/,
  );

  const handle = pubkey.decryptHandle(opening);
  const handleBytes = handle.toBytes();
  assert.deepStrictEqual(handleBytes, one.handle().toBytes());
  const otherOpening = new PedersenOpening();
  const otherHandle = pubkey.decryptHandle(otherOpening);
  const otherHandleBytes = otherHandle.toBytes();
  assert.deepStrictEqual(
    handle.add(otherHandle).toBytes(),
    pubkey.decryptHandle(opening.add(otherOpening)).toBytes(),
  );
  assert.deepStrictEqual(
    handle.subtract(otherHandle).toBytes(),
    pubkey.decryptHandle(opening.subtract(otherOpening)).toBytes(),
  );
  assert.deepStrictEqual(handle.subtract(handle).toBytes(), new Uint8Array(32));
  for (const scalar of [0n, 1n, 7n, maxU64]) {
    assert.deepStrictEqual(
      handle.multiplyByU64(scalar).toBytes(),
      pubkey.decryptHandle(opening.multiplyByU64(scalar)).toBytes(),
    );
  }
  assert.deepStrictEqual(handle.toBytes(), handleBytes);
  assert.deepStrictEqual(otherHandle.toBytes(), otherHandleBytes);

  const recipients = [keypair, new ElGamalKeypair(), new ElGamalKeypair()];
  for (const [GroupedCiphertext, count] of [
    [GroupedElGamalCiphertext2Handles, 2],
    [GroupedElGamalCiphertext3Handles, 3],
  ]) {
    const keys = recipients.slice(0, count);
    const grouped = GroupedCiphertext.encryptWith(
      ...keys.map((recipient) => recipient.pubkey()),
      42n,
      opening,
    );
    const groupedBytes = grouped.toBytes();
    const recovered = GroupedCiphertext.fromBytes(groupedBytes);
    for (const [index, recipient] of keys.entries()) {
      const extracted = recovered.toElGamalCiphertext(index);
      assert.deepStrictEqual(
        extracted.toBytes(),
        recipient.pubkey().encryptWith(42n, opening).toBytes(),
      );
      assert.strictEqual(recipient.secret().decrypt(extracted), 42n);
      assert.strictEqual(recovered.decrypt(recipient.secret(), index), 42n);
    }
    for (const index of [count, -1, 1.5, 2 ** 32, NaN, undefined]) {
      assert.throws(
        () => recovered.toElGamalCiphertext(index),
        /Invalid handle index/,
      );
      assert.throws(
        () => recovered.decrypt(keys[0].secret(), index),
        /Invalid handle index/,
      );
    }
    assert.deepStrictEqual(recovered.toBytes(), groupedBytes);
  }

  console.log("✅ Node.js integration tests passed!");
} catch (error) {
  console.error("❌ Node.js integration tests failed:", error);
  process.exit(1);
}
