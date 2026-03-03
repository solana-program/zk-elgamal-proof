import test from 'ava';
import {
  createDefaultSolanaClient,
  generateKeyPairSignerWithSol,
  sendAndConfirmInstructions,
} from './_setup';
import { verifyBatchedRangeProofU64 } from '../src';
import { BatchedRangeProofU64Data, PedersenCommitment, PedersenOpening } from '@solana/zk-sdk/node';
import { generateKeyPairSigner } from '@solana/kit';
import {
  createRecord,
  createWriteInstruction,
  RECORD_META_DATA_SIZE,
  RECORD_CHUNK_SIZE_POST_INITIALIZE,
} from '@solana-program/record';

const createValidProof = () => {
  const amount1 = 255n; // 8-bit max
  const amount2 = (1n << 56n) - 1n; // 56-bit max

  const opening1 = new PedersenOpening();
  const opening2 = new PedersenOpening();

  const commitment1 = PedersenCommitment.from(amount1, opening1);
  const commitment2 = PedersenCommitment.from(amount2, opening2);

  const commitments = [commitment1, commitment2];
  const amounts = new BigUint64Array([amount1, amount2]);
  const bitLengths = new Uint8Array([8, 56]);
  const openings = [opening1, opening2];

  return new BatchedRangeProofU64Data(commitments, amounts, bitLengths, openings);
};

test('verifyBatchedRangeProofU64: success with valid proof (no context state)', async t => {
  const client = createDefaultSolanaClient();
  const payer = await generateKeyPairSignerWithSol(client);

  // Generate VALID proof
  const proof = createValidProof();

  // Verify Ephemerally
  const ixs = await verifyBatchedRangeProofU64({
    rpc: client.rpc,
    payer,
    proofData: proof.toBytes(),
    // No contextState
  });

  await t.notThrowsAsync(async () => {
    await sendAndConfirmInstructions(client, payer, ixs);
  }, 'Ephemeral verification should succeed within transaction limits');
});

test('verifyBatchedRangeProofU64: success with valid proof (context state)', async t => {
  const client = createDefaultSolanaClient();
  const payer = await generateKeyPairSignerWithSol(client);
  const contextAccount = await generateKeyPairSigner();

  const proof = createValidProof();

  // Generate instructions (CreateAccount + Verify)
  const ixs = await verifyBatchedRangeProofU64({
    rpc: client.rpc,
    payer,
    proofData: proof.toBytes(),
    contextState: {
      contextAccount,
      authority: payer.address,
    },
  });

  // The proof is large, we send them in two separate transactions.
  const createIx = ixs[0];
  const verifyIx = ixs[1];

  // Create Context Account
  await sendAndConfirmInstructions(client, payer, [createIx]);

  // Verify Proof
  await sendAndConfirmInstructions(client, payer, [verifyIx]);

  const account = await client.rpc
    .getAccountInfo(contextAccount.address, { encoding: 'base64' })
    .send();

  t.truthy(account.value, 'Context state account was created');
});

test('verifyBatchedRangeProofU64: proof in record account (no context state)', async t => {
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
  const verifyIxs = await verifyBatchedRangeProofU64({
    rpc: client.rpc,
    payer,
    proofData: {
      account: recordKeypair.address,
      offset: Number(RECORD_META_DATA_SIZE),
    },
    // No context state
  });

  // This verification is small (just offset), so it fits easily.
  await t.notThrowsAsync(async () => {
    await sendAndConfirmInstructions(client, payer, verifyIxs);
  }, 'Verification should succeed using data from record account');
});

test('verifyBatchedRangeProofU64: proof in record account (context state)', async t => {
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
  const verifyIxs = await verifyBatchedRangeProofU64({
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
