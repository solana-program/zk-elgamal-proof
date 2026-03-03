import test from 'ava';
import {
  createDefaultSolanaClient,
  generateKeyPairSignerWithSol,
  sendAndConfirmInstructions,
} from './_setup';
import { generateKeyPairSigner } from '@solana/kit';
import { verifyZeroCiphertext, closeContextStateProof } from '../src';
import { ElGamalKeypair, ZeroCiphertextProofData } from '@solana/zk-sdk/node';

test('closeContextState: can close a verified proof context', async t => {
  const client = createDefaultSolanaClient();
  const payer = await generateKeyPairSignerWithSol(client);
  const contextAccount = await generateKeyPairSigner();
  const destination = await generateKeyPairSigner(); // For rent

  const keypair = new ElGamalKeypair();
  const ciphertext = keypair.pubkey().encryptU64(0n);
  const proof = new ZeroCiphertextProofData(keypair, ciphertext);

  const verifyIxs = await verifyZeroCiphertext({
    rpc: client.rpc,
    payer,
    proofData: proof.toBytes(),
    contextState: {
      contextAccount,
      authority: payer.address,
    },
  });
  await sendAndConfirmInstructions(client, payer, verifyIxs);

  // Verify existence
  let accountInfo = await client.rpc
    .getAccountInfo(contextAccount.address, { encoding: 'base64' })
    .send();
  t.truthy(accountInfo.value, 'Account should exist before closing');

  const closeIx = closeContextStateProof({
    contextState: contextAccount.address,
    authority: payer, // Must match the authority set in Step 1
    destination: destination.address,
  });

  await sendAndConfirmInstructions(client, payer, [closeIx]);

  // Account should be gone (null)
  accountInfo = await client.rpc
    .getAccountInfo(contextAccount.address, { encoding: 'base64' })
    .send();
  t.is(accountInfo.value, null, 'Account should be closed (null)');

  // Destination should have received lamports (rent)
  const destBalance = await client.rpc.getBalance(destination.address).send();
  t.true(destBalance.value > 0n, 'Destination should have received rent');
});
