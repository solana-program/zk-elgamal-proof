import test from 'ava';
import {
  createDefaultSolanaClient,
  generateKeyPairSignerWithSol,
  sendAndConfirmInstructions,
} from './_setup';
import { generateKeyPairSigner } from '@solana/kit';
import { verifyGroupedCiphertext3HandlesValidity } from '../src';
import {
  ElGamalKeypair,
  GroupedCiphertext3HandlesValidityProofData,
  GroupedElGamalCiphertext3Handles,
  PedersenOpening,
} from '@solana/zk-sdk/node';
import {
  createRecord,
  createWriteInstruction,
  RECORD_META_DATA_SIZE,
  RECORD_CHUNK_SIZE_POST_INITIALIZE,
} from '@solana-program/record';

const createValidProof = () => {
  const destination1 = new ElGamalKeypair();
  const destination2 = new ElGamalKeypair();
  const destination3 = new ElGamalKeypair();
  const amount = 100n;
  const opening = new PedersenOpening();

  // Create a valid grouped ciphertext for 3 handles
  const groupedCiphertext = GroupedElGamalCiphertext3Handles.encryptWith(
    destination1.pubkey(),
    destination2.pubkey(),
    destination3.pubkey(),
    amount,
    opening,
  );

  return new GroupedCiphertext3HandlesValidityProofData(
    destination1.pubkey(),
    destination2.pubkey(),
    destination3.pubkey(),
    groupedCiphertext,
    amount,
    opening,
  );
};

test('verifyGroupedCiphertext3HandlesValidity: success with valid proof (no context state)', async t => {
  const client = createDefaultSolanaClient();
  const payer = await generateKeyPairSignerWithSol(client);

  const proof = createValidProof();
  const proofData = proof.toBytes();

  // Verify WITHOUT Context
  const ixs = await verifyGroupedCiphertext3HandlesValidity({
    rpc: client.rpc,
    payer,
    proofData,
    // contextState is undefined
  });

  await t.notThrowsAsync(async () => {
    await sendAndConfirmInstructions(client, payer, ixs);
  });

  t.pass('Ephemeral verification succeeded');
});

test('verifyGroupedCiphertext3HandlesValidity: handles invalid proof data gracefully', async t => {
  const client = createDefaultSolanaClient();
  const payer = await generateKeyPairSignerWithSol(client);

  // Use dummy bytes
  const dummyProofData = new Uint8Array(256).fill(0);

  await t.throwsAsync(async () => {
    const ixs = await verifyGroupedCiphertext3HandlesValidity({
      rpc: client.rpc,
      payer,
      proofData: dummyProofData,
    });

    await sendAndConfirmInstructions(client, payer, ixs);
  });

  t.pass('Transaction was rejected as expected');
});

test('verifyGroupedCiphertext3HandlesValidity: success with valid proof (context state)', async t => {
  const client = createDefaultSolanaClient();
  const payer = await generateKeyPairSignerWithSol(client);
  const contextAccount = await generateKeyPairSigner();

  const proof = createValidProof();
  const proofData = proof.toBytes();

  const ixs = await verifyGroupedCiphertext3HandlesValidity({
    rpc: client.rpc,
    payer,
    proofData,
    contextState: {
      contextAccount,
      authority: payer.address,
    },
  });

  await sendAndConfirmInstructions(client, payer, ixs);

  // Context State Account should exist
  const account = await client.rpc
    .getAccountInfo(contextAccount.address, { encoding: 'base64' })
    .send();

  t.truthy(account.value, 'Context state account was created');
});

test('verifyGroupedCiphertext3HandlesValidity: proof in record account (no context state)', async t => {
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

  // Write Proof to Record
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
  const verifyIxs = await verifyGroupedCiphertext3HandlesValidity({
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

test('verifyGroupedCiphertext3HandlesValidity: proof in record account (context state)', async t => {
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

  // Write Proof to Record
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
  const verifyIxs = await verifyGroupedCiphertext3HandlesValidity({
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
