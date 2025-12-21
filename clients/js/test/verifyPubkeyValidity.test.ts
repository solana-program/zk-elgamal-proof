import test from 'ava';
import {
  createDefaultSolanaClient,
  generateKeyPairSignerWithSol,
  sendAndConfirmInstructions,
} from './_setup';
import { generateKeyPairSigner } from '@solana/kit';
import { verifyPubkeyValidity } from '../src';
import { ElGamalKeypair, PubkeyValidityProofData } from '@solana/zk-sdk/node';

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
