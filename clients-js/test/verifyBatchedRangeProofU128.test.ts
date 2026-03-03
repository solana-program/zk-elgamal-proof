import test from 'ava';
import {
  createDefaultSolanaClient,
  generateKeyPairSignerWithSol,
  sendAndConfirmInstructions,
} from './_setup';
import { verifyBatchedRangeProofU128 } from '../src';
import {
  BatchedRangeProofU128Data,
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

const createValidProof = () => {
  // Sum of bit lengths must be 128
  const amount1 = (1n << 64n) - 1n; // 64-bit max
  const amount2 = 100n; // arbitrary 64-bit number

  const opening1 = new PedersenOpening();
  const opening2 = new PedersenOpening();

  const commitment1 = PedersenCommitment.from(amount1, opening1);
  const commitment2 = PedersenCommitment.from(amount2, opening2);

  const commitments = [commitment1, commitment2];
  const amounts = new BigUint64Array([amount1, amount2]);
  const bitLengths = new Uint8Array([64, 64]); // 64 + 64 = 128
  const openings = [opening1, opening2];

  return new BatchedRangeProofU128Data(commitments, amounts, bitLengths, openings);
};

test('verifyBatchedRangeProofU128: success (ephemeral, no context state)', async t => {
  const client = createDefaultSolanaClient();
  const payer = await generateKeyPairSignerWithSol(client);

  const proof = createValidProof();

  // Verify Ephemerally
  const ixs = await verifyBatchedRangeProofU128({
    rpc: client.rpc,
    payer,
    proofData: proof.toBytes(),
    // No contextState
  });

  await t.notThrowsAsync(async () => {
    await sendAndConfirmInstructions(client, payer, ixs);
  }, 'Ephemeral verification should succeed');
});

test('verifyBatchedRangeProofU128: success (context state)', async t => {
  const client = createDefaultSolanaClient();
  const payer = await generateKeyPairSignerWithSol(client);
  const contextAccount = await generateKeyPairSigner();

  const proof = createValidProof();

  const ixs = await verifyBatchedRangeProofU128({
    rpc: client.rpc,
    payer,
    proofData: proof.toBytes(),
    contextState: {
      contextAccount,
      authority: payer.address,
    },
  });

  // Split transaction: Create Context first, then Verify
  // Necessary because proof + context creation exceeds legacy tx limits
  const createIx = ixs[0];
  const verifyIx = ixs[1];

  await sendAndConfirmInstructions(client, payer, [createIx]);
  await sendAndConfirmInstructions(client, payer, [verifyIx]);

  const account = await client.rpc
    .getAccountInfo(contextAccount.address, { encoding: 'base64' })
    .send();

  t.truthy(account.value, 'Context state account was created');
});

test('verifyBatchedRangeProofU128: proof in record account (no context state)', async t => {
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
  const verifyIxs = await verifyBatchedRangeProofU128({
    rpc: client.rpc,
    payer,
    proofData: {
      account: recordKeypair.address,
      offset: Number(RECORD_META_DATA_SIZE),
    },
    // No context state
  });

  await t.notThrowsAsync(async () => {
    await sendAndConfirmInstructions(client, payer, verifyIxs);
  }, 'Verification should succeed using data from record account');
});

test('verifyBatchedRangeProofU128: proof in record account (context state)', async t => {
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
  const verifyIxs = await verifyBatchedRangeProofU128({
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

  await sendAndConfirmInstructions(client, payer, verifyIxs);

  const account = await client.rpc
    .getAccountInfo(contextAccount.address, { encoding: 'base64' })
    .send();

  t.truthy(account.value, 'Context state account was created from proof in record account');
});
