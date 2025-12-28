import test from 'ava';
import {
  createDefaultSolanaClient,
  generateKeyPairSignerWithSol,
  sendAndConfirmInstructions,
} from './_setup';
import { generateKeyPairSigner } from '@solana/kit';
import { verifyPubkeyValidity } from '../src';
import { ElGamalKeypair, PubkeyValidityProofData } from '@solana/zk-sdk/node';
import {
  createRecord,
  createWriteInstruction,
  RECORD_META_DATA_SIZE,
} from '@solana-program/record';

test('verifyPubkeyValidity: success with valid proof (no context state)', async t => {
  const client = createDefaultSolanaClient();
  const payer = await generateKeyPairSignerWithSol(client);

  // Generate VALID proof
  const keypair = new ElGamalKeypair();
  const proof = new PubkeyValidityProofData(keypair);
  const proofData = proof.toBytes();

  // Verify WITHOUT Context
  // This verifies the proof ephemerally (just for this transaction) and discards it.
  const ixs = await verifyPubkeyValidity({
    rpc: client.rpc,
    payer,
    proofData,
    // contextState is undefined
  });

  // Send Transaction
  // If the proof was invalid, this would throw.
  // If the logic was wrong (e.g. sending accounts when none expected), this would throw.
  await t.notThrowsAsync(async () => {
    await sendAndConfirmInstructions(client, payer, ixs);
  });

  t.pass('Ephemeral verification succeeded');
});

test('verifyPubkeyValidity: success with valid proof (context state)', async t => {
  const client = createDefaultSolanaClient();
  const payer = await generateKeyPairSignerWithSol(client);
  const contextAccount = await generateKeyPairSigner();

  const keypair = new ElGamalKeypair();
  const proof = new PubkeyValidityProofData(keypair);
  const proofData = proof.toBytes();

  const ixs = await verifyPubkeyValidity({
    rpc: client.rpc,
    payer,
    proofData,
    contextState: {
      contextAccount,
      authority: payer.address,
    },
  });

  await sendAndConfirmInstructions(client, payer, ixs);

  const account = await client.rpc
    .getAccountInfo(contextAccount.address, { encoding: 'base64' })
    .send();

  t.truthy(account.value, 'Context state account was created');
});

test('verifyPubkeyValidity: handles invalid proof data gracefully', async t => {
  const client = createDefaultSolanaClient();
  const payer = await generateKeyPairSignerWithSol(client);

  // Use dummy bytes
  const dummyProofData = new Uint8Array(64).fill(0);

  await t.throwsAsync(async () => {
    const ixs = await verifyPubkeyValidity({
      rpc: client.rpc,
      payer,
      proofData: dummyProofData,
    });

    await sendAndConfirmInstructions(client, payer, ixs);
  });

  t.pass('Transaction was rejected as expected');
});

test('verifyPubkeyValidity: proof in record account (no context state)', async t => {
  const client = createDefaultSolanaClient();
  const payer = await generateKeyPairSignerWithSol(client);

  // Generate Valid Proof
  const keypair = new ElGamalKeypair();
  const proof = new PubkeyValidityProofData(keypair);
  const proofData = proof.toBytes();

  // Initialize Record Account
  const recordAuthority = await generateKeyPairSigner();
  const { recordKeypair, ixs: initIxs } = await createRecord({
    rpc: client.rpc,
    payer,
    authority: recordAuthority.address,
    dataLength: BigInt(proofData.length),
  });

  // Write Proof to Record
  const writeIx = createWriteInstruction({
    recordAccount: recordKeypair.address,
    authority: recordAuthority,
    offset: 0n,
    data: proofData,
  });

  await sendAndConfirmInstructions(client, payer, [...initIxs, writeIx]);

  // 4. Verify using Record Account
  const verifyIxs = await verifyPubkeyValidity({
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

test('verifyPubkeyValidity: proof in record account (context state)', async t => {
  const client = createDefaultSolanaClient();
  const payer = await generateKeyPairSignerWithSol(client);
  const contextAccount = await generateKeyPairSigner();

  // Generate Valid Proof
  const keypair = new ElGamalKeypair();
  const proof = new PubkeyValidityProofData(keypair);
  const proofData = proof.toBytes();

  // Initialize Record Account
  const recordAuthority = await generateKeyPairSigner();
  const { recordKeypair, ixs: initIxs } = await createRecord({
    rpc: client.rpc,
    payer,
    authority: recordAuthority.address,
    dataLength: BigInt(proofData.length),
  });

  // Write Proof to Record
  const writeIx = createWriteInstruction({
    recordAccount: recordKeypair.address,
    authority: recordAuthority,
    offset: 0n,
    data: proofData,
  });

  await sendAndConfirmInstructions(client, payer, [...initIxs, writeIx]);

  // Verify using Record Account AND Create Context State
  const verifyIxs = await verifyPubkeyValidity({
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
