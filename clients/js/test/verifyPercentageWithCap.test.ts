import test from 'ava';
import {
  createDefaultSolanaClient,
  generateKeyPairSignerWithSol,
  sendAndConfirmInstructions,
} from './_setup';
import { generateKeyPairSigner } from '@solana/kit';
import { verifyPercentageWithCap } from '../src';
import {
  PedersenCommitment,
  PedersenOpening,
  PercentageWithCapProofData,
} from '@solana/zk-sdk/node';

test('verifyPercentageWithCap: success with valid proof (no context state)', async t => {
  const client = createDefaultSolanaClient();
  const payer = await generateKeyPairSignerWithSol(client);

  // Generate VALID proof
  const maxValue = 3n;
  // percentageRate not explicitly used in proof constructor but part of logical setup
  const percentageAmount = 1n;
  const deltaAmount = 9600n;

  const percentageOpening = new PedersenOpening();
  const percentageCommitment = PedersenCommitment.from(percentageAmount, percentageOpening);

  const deltaOpening = new PedersenOpening();
  const deltaCommitment = PedersenCommitment.from(deltaAmount, deltaOpening);

  const claimedOpening = new PedersenOpening();
  const claimedCommitment = PedersenCommitment.from(deltaAmount, claimedOpening);

  const proof = new PercentageWithCapProofData(
    percentageCommitment,
    percentageOpening,
    percentageAmount,
    deltaCommitment,
    deltaOpening,
    deltaAmount,
    claimedCommitment,
    claimedOpening,
    maxValue,
  );
  const proofData = proof.toBytes();

  const ixs = await verifyPercentageWithCap({
    rpc: client.rpc,
    payer,
    proofData,
  });

  await t.notThrowsAsync(async () => {
    await sendAndConfirmInstructions(client, payer, ixs);
  });

  t.pass('Ephemeral verification succeeded');
});

test('verifyPercentageWithCap: success with valid proof (context state)', async t => {
  const client = createDefaultSolanaClient();
  const payer = await generateKeyPairSignerWithSol(client);
  const contextAccount = await generateKeyPairSigner();

  const maxValue = 3n;
  const percentageAmount = 1n;
  const deltaAmount = 9600n;

  const percentageOpening = new PedersenOpening();
  const percentageCommitment = PedersenCommitment.from(percentageAmount, percentageOpening);

  const deltaOpening = new PedersenOpening();
  const deltaCommitment = PedersenCommitment.from(deltaAmount, deltaOpening);

  const claimedOpening = new PedersenOpening();
  const claimedCommitment = PedersenCommitment.from(deltaAmount, claimedOpening);

  const proof = new PercentageWithCapProofData(
    percentageCommitment,
    percentageOpening,
    percentageAmount,
    deltaCommitment,
    deltaOpening,
    deltaAmount,
    claimedCommitment,
    claimedOpening,
    maxValue,
  );

  const ixs = await verifyPercentageWithCap({
    rpc: client.rpc,
    payer,
    proofData: proof.toBytes(),
    contextState: {
      contextAccount,
      authority: payer,
    },
  });

  await sendAndConfirmInstructions(client, payer, ixs);

  const account = await client.rpc
    .getAccountInfo(contextAccount.address, { encoding: 'base64' })
    .send();

  t.truthy(account.value, 'Context state account was created');
});

test('verifyPercentageWithCap: handles invalid proof data gracefully', async t => {
  const client = createDefaultSolanaClient();
  const payer = await generateKeyPairSignerWithSol(client);

  const dummyProofData = new Uint8Array(128).fill(0);

  await t.throwsAsync(async () => {
    const ixs = await verifyPercentageWithCap({
      rpc: client.rpc,
      payer,
      proofData: dummyProofData,
    });

    await sendAndConfirmInstructions(client, payer, ixs);
  });

  t.pass('Transaction was rejected as expected');
});
