import test from 'ava';
import {
  createDefaultSolanaClient,
  generateKeyPairSignerWithSol,
  sendAndConfirmInstructions,
} from './_setup';
import { verifyBatchedRangeProofU256 } from '../src';
import {
  BatchedRangeProofU256Data,
  PedersenCommitment,
  PedersenOpening,
} from '@solana/zk-sdk/node';
import { generateKeyPairSigner } from '@solana/kit';
import {
  createRecord,
  createWriteInstruction,
  RECORD_META_DATA_SIZE,
  RECORD_CHUNK_SIZE_POST_INITIALIZE,
} from '@solana-program/record';
import { getSetComputeUnitLimitInstruction } from '@solana-program/compute-budget';

const createValidProof = () => {
  // Sum of bit lengths must be 256.
  // We use four 64-bit commitments: 64 * 4 = 256.
  const amount1 = (1n << 64n) - 1n; // 64-bit max
  const amount2 = 500n; // arbitrary valid amount
  const amount3 = 12345n; // arbitrary valid amount
  const amount4 = 0n; // zero is valid

  const opening1 = new PedersenOpening();
  const opening2 = new PedersenOpening();
  const opening3 = new PedersenOpening();
  const opening4 = new PedersenOpening();

  const commitment1 = PedersenCommitment.from(amount1, opening1);
  const commitment2 = PedersenCommitment.from(amount2, opening2);
  const commitment3 = PedersenCommitment.from(amount3, opening3);
  const commitment4 = PedersenCommitment.from(amount4, opening4);

  const commitments = [commitment1, commitment2, commitment3, commitment4];
  const amounts = new BigUint64Array([amount1, amount2, amount3, amount4]);
  const bitLengths = new Uint8Array([64, 64, 64, 64]);
  const openings = [opening1, opening2, opening3, opening4];

  return new BatchedRangeProofU256Data(commitments, amounts, bitLengths, openings);
};

test('verifyBatchedRangeProofU256: proof in record account (no context state)', async t => {
  const client = createDefaultSolanaClient();
  const payer = await generateKeyPairSignerWithSol(client);

  const proof = createValidProof();
  const proofData = proof.toBytes();

  // Initialize Record Account
  const recordAuthority = await generateKeyPairSigner();
  const { recordKeypair, ixs: initIxs } = await createRecord({
    rpc: client.rpc,
    payer,
    authority: recordAuthority.address,
    dataLength: BigInt(proofData.length),
  });

  await sendAndConfirmInstructions(client, payer, initIxs);

  // Write Proof to Record in Chunks
  let offset = 0;
  while (offset < proofData.length) {
    const chunkEnd = Math.min(offset + RECORD_CHUNK_SIZE_POST_INITIALIZE, proofData.length);
    const chunk = proofData.slice(offset, chunkEnd);

    const writeIx = createWriteInstruction({
      recordAccount: recordKeypair.address,
      authority: recordAuthority,
      offset: BigInt(offset),
      data: chunk,
    });

    await sendAndConfirmInstructions(client, payer, [writeIx]);
    offset += RECORD_CHUNK_SIZE_POST_INITIALIZE;
  }

  // Verify using Record Account
  const verifyIxs = await verifyBatchedRangeProofU256({
    rpc: client.rpc,
    payer,
    proofData: {
      account: recordKeypair.address,
      offset: Number(RECORD_META_DATA_SIZE),
    },
    // No context state
  });

  const computeIx = getSetComputeUnitLimitInstruction({ units: 500_000 });

  await t.notThrowsAsync(async () => {
    await sendAndConfirmInstructions(client, payer, [computeIx, ...verifyIxs]);
  }, 'Verification should succeed using data from record account');
});

test('verifyBatchedRangeProofU256: proof in record account (context state)', async t => {
  const client = createDefaultSolanaClient();
  const payer = await generateKeyPairSignerWithSol(client);
  const contextAccount = await generateKeyPairSigner();

  const proof = createValidProof();
  const proofData = proof.toBytes();

  // Initialize Record Account
  const recordAuthority = await generateKeyPairSigner();
  const { recordKeypair, ixs: initIxs } = await createRecord({
    rpc: client.rpc,
    payer,
    authority: recordAuthority.address,
    dataLength: BigInt(proofData.length),
  });

  await sendAndConfirmInstructions(client, payer, initIxs);

  // Write Proof to Record in Chunks
  let offset = 0;
  while (offset < proofData.length) {
    const chunkEnd = Math.min(offset + RECORD_CHUNK_SIZE_POST_INITIALIZE, proofData.length);
    const chunk = proofData.slice(offset, chunkEnd);

    const writeIx = createWriteInstruction({
      recordAccount: recordKeypair.address,
      authority: recordAuthority,
      offset: BigInt(offset),
      data: chunk,
    });

    await sendAndConfirmInstructions(client, payer, [writeIx]);
    offset += RECORD_CHUNK_SIZE_POST_INITIALIZE;
  }

  // Verify using Record Account AND Create Context State
  const verifyIxs = await verifyBatchedRangeProofU256({
    rpc: client.rpc,
    payer,
    proofData: {
      account: recordKeypair.address,
      offset: Number(RECORD_META_DATA_SIZE),
    },
    contextState: {
      contextAccount,
      authority: payer.address,
    },
  });

  const computeIx = getSetComputeUnitLimitInstruction({ units: 500_000 });
  await sendAndConfirmInstructions(client, payer, [computeIx, ...verifyIxs]);

  const account = await client.rpc
    .getAccountInfo(contextAccount.address, { encoding: 'base64' })
    .send();

  t.truthy(account.value, 'Context state account was created from proof in record account');
});
