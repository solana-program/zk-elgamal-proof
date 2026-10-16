import test from 'ava';
import {
  address,
  generateKeyPairSigner,
  GetMinimumBalanceForRentExemptionApi,
  lamports,
  Rpc,
} from '@solana/kit';
import {
  closeContextStateProof,
  verifyPubkeyValidity,
  ZK_ELGAMAL_PROOF_PROGRAM_ADDRESS,
} from '../src';

// Only `getMinimumBalanceForRentExemption` is needed to build the instructions.
const rpc = {
  getMinimumBalanceForRentExemption: () => ({ send: () => Promise.resolve(lamports(1_000_000n)) }),
} as unknown as Rpc<GetMinimumBalanceForRentExemptionApi>;

const PROOF_ACCOUNT = address('11111111111111111111111111111112');
const DESTINATION = address('SysvarRent111111111111111111111111111111111');

test('closeContextStateProof: accepts address wrappers', async t => {
  const [authority, contextState] = await Promise.all([
    generateKeyPairSigner(),
    generateKeyPairSigner(),
  ]);

  const fromAddresses = closeContextStateProof({
    contextState: contextState.address,
    authority,
    destination: DESTINATION,
    programId: ZK_ELGAMAL_PROOF_PROGRAM_ADDRESS,
  });
  const fromWrappers = closeContextStateProof({
    contextState: { address: contextState.address },
    authority,
    destination: { address: DESTINATION },
    programId: { address: ZK_ELGAMAL_PROOF_PROGRAM_ADDRESS },
  });

  t.deepEqual(fromWrappers, fromAddresses);
});

test('verifyPubkeyValidity: accepts address wrappers', async t => {
  const [payer, contextAccount, authority] = await Promise.all([
    generateKeyPairSigner(),
    generateKeyPairSigner(),
    generateKeyPairSigner(),
  ]);

  const fromAddresses = await verifyPubkeyValidity({
    rpc,
    payer,
    proofData: { account: PROOF_ACCOUNT, offset: 0 },
    contextState: { contextAccount, authority: authority.address },
    programId: ZK_ELGAMAL_PROOF_PROGRAM_ADDRESS,
  });
  const fromWrappers = await verifyPubkeyValidity({
    rpc,
    payer,
    proofData: { account: { address: PROOF_ACCOUNT }, offset: 0 },
    contextState: { contextAccount, authority: { address: authority.address } },
    programId: { address: ZK_ELGAMAL_PROOF_PROGRAM_ADDRESS },
  });

  t.deepEqual(fromWrappers, fromAddresses);
  // The context state account is created and owned by the (unwrapped) program address.
  t.is(fromWrappers.length, 2);
  t.is(fromWrappers[1].programAddress, ZK_ELGAMAL_PROOF_PROGRAM_ADDRESS);
});
