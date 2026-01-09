import test from 'ava';
import {
  createDefaultSolanaClient,
  generateKeyPairSignerWithSol,
  sendAndConfirmInstructions,
} from './_setup';
import { generateKeyPairSigner } from '@solana/kit';
import { verifyCiphertextCiphertextEquality } from '../src';
import {
  ElGamalKeypair,
  CiphertextCiphertextEqualityProofData,
  PedersenOpening,
} from '@solana/zk-sdk/node';
import {
  createRecord,
  createWriteInstruction,
  RECORD_META_DATA_SIZE,
} from '@solana-program/record';

test('verifyCiphertextCiphertextEquality: success with valid proof (no context state)', async t => {
  const client = createDefaultSolanaClient();
  const payer = await generateKeyPairSignerWithSol(client);

  // Generate VALID proof
  const keypair1 = new ElGamalKeypair();
  const keypair2 = new ElGamalKeypair();
  const amount = 55n;

  const ciphertext1 = keypair1.pubkey().encryptU64(amount);

  const opening2 = new PedersenOpening();
  const ciphertext2 = keypair2.pubkey().encryptWith(amount, opening2);

  const proof = new CiphertextCiphertextEqualityProofData(
    keypair1,
    keypair2.pubkey(),
    ciphertext1,
    ciphertext2,
    opening2,
    amount,
  );
  const proofData = proof.toBytes();

  // Verify WITHOUT Context
  const ixs = await verifyCiphertextCiphertextEquality({
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

test('verifyCiphertextCiphertextEquality: handles invalid proof data gracefully', async t => {
  const client = createDefaultSolanaClient();
  const payer = await generateKeyPairSignerWithSol(client);

  // Use dummy bytes (approximate size of a valid proof)
  const dummyProofData = new Uint8Array(224).fill(0);

  await t.throwsAsync(async () => {
    const ixs = await verifyCiphertextCiphertextEquality({
      rpc: client.rpc,
      payer,
      proofData: dummyProofData,
    });

    await sendAndConfirmInstructions(client, payer, ixs);
  });

  t.pass('Transaction was rejected as expected');
});

test('verifyCiphertextCiphertextEquality: success with valid proof (context state)', async t => {
  const client = createDefaultSolanaClient();
  const payer = await generateKeyPairSignerWithSol(client);
  const contextAccount = await generateKeyPairSigner();

  // Generate VALID proof
  const keypair1 = new ElGamalKeypair();
  const keypair2 = new ElGamalKeypair();
  const amount = 77n;

  const ciphertext1 = keypair1.pubkey().encryptU64(amount);

  const opening2 = new PedersenOpening();
  const ciphertext2 = keypair2.pubkey().encryptWith(amount, opening2);

  const proof = new CiphertextCiphertextEqualityProofData(
    keypair1,
    keypair2.pubkey(),
    ciphertext1,
    ciphertext2,
    opening2,
    amount,
  );
  const proofData = proof.toBytes();

  const ixs = await verifyCiphertextCiphertextEquality({
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

test('verifyCiphertextCiphertextEquality: proof in record account (no context state)', async t => {
  const client = createDefaultSolanaClient();
  const payer = await generateKeyPairSignerWithSol(client);

  // Generate Valid Proof
  const keypair1 = new ElGamalKeypair();
  const keypair2 = new ElGamalKeypair();
  const amount = 100n;

  const ciphertext1 = keypair1.pubkey().encryptU64(amount);
  const opening2 = new PedersenOpening();
  const ciphertext2 = keypair2.pubkey().encryptWith(amount, opening2);

  const proof = new CiphertextCiphertextEqualityProofData(
    keypair1,
    keypair2.pubkey(),
    ciphertext1,
    ciphertext2,
    opening2,
    amount,
  );
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

  // Verify using Record Account
  const verifyIxs = await verifyCiphertextCiphertextEquality({
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

test('verifyCiphertextCiphertextEquality: proof in record account (context state)', async t => {
  const client = createDefaultSolanaClient();
  const payer = await generateKeyPairSignerWithSol(client);
  const contextAccount = await generateKeyPairSigner();

  // Generate Valid Proof
  const keypair1 = new ElGamalKeypair();
  const keypair2 = new ElGamalKeypair();
  const amount = 255n;

  const ciphertext1 = keypair1.pubkey().encryptU64(amount);
  const opening2 = new PedersenOpening();
  const ciphertext2 = keypair2.pubkey().encryptWith(amount, opening2);

  const proof = new CiphertextCiphertextEqualityProofData(
    keypair1,
    keypair2.pubkey(),
    ciphertext1,
    ciphertext2,
    opening2,
    amount,
  );
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
  const verifyIxs = await verifyCiphertextCiphertextEquality({
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
