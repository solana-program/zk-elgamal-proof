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

test('verifyBatchedRangeProofU128: success (64-bit + 64-bit)', async t => {
  const client = createDefaultSolanaClient();
  const payer = await generateKeyPairSignerWithSol(client);

  const amount1 = 100n;
  const amount2 = 200n;

  const opening1 = new PedersenOpening();
  const opening2 = new PedersenOpening();

  const commitment1 = PedersenCommitment.from(amount1, opening1);
  const commitment2 = PedersenCommitment.from(amount2, opening2);

  const commitments = [commitment1, commitment2];
  const amounts = new BigUint64Array([amount1, amount2]);
  const bitLengths = new Uint8Array([64, 64]);
  const openings = [opening1, opening2];

  const proof = new BatchedRangeProofU128Data(commitments, amounts, bitLengths, openings);

  const ixs = await verifyBatchedRangeProofU128({
    rpc: client.rpc,
    payer,
    proofData: proof.toBytes(),
  });

  await t.notThrowsAsync(async () => {
    await sendAndConfirmInstructions(client, payer, ixs);
  });
});
