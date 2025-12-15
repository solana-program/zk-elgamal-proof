import test from 'ava';
import {
  createDefaultSolanaClient,
  generateKeyPairSignerWithSol,
  sendAndConfirmInstructions,
} from './_setup';
import { verifyBatchedRangeProofU64 } from '../src';
import { BatchedRangeProofU64Data, PedersenCommitment, PedersenOpening } from '@solana/zk-sdk/node';

test('verifyBatchedRangeProofU64: success (8-bit + 56-bit)', async t => {
  const client = createDefaultSolanaClient();
  const payer = await generateKeyPairSignerWithSol(client);

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

  const proof = new BatchedRangeProofU64Data(commitments, amounts, bitLengths, openings);

  const ixs = await verifyBatchedRangeProofU64({
    rpc: client.rpc,
    payer,
    proofData: proof.toBytes(),
  });

  await t.notThrowsAsync(async () => {
    await sendAndConfirmInstructions(client, payer, ixs);
  });
});
