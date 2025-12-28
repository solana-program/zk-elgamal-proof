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
import {
  createRecord,
  createWriteInstruction,
  RECORD_META_DATA_SIZE,
} from '@solana-program/record';

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
      authority: payer.address,
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

test('verifyPercentageWithCap: proof in record account (no context state)', async t => {
  const client = createDefaultSolanaClient();
  const payer = await generateKeyPairSignerWithSol(client);

  // Generate VALID proof
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

  // Verify using Record Account (No Context State)
  const verifyIxs = await verifyPercentageWithCap({
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

test('verifyPercentageWithCap: proof in record account (context state)', async t => {
  const client = createDefaultSolanaClient();
  const payer = await generateKeyPairSignerWithSol(client);
  const contextAccount = await generateKeyPairSigner();

  // Generate VALID proof
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
  const verifyIxs = await verifyPercentageWithCap({
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
