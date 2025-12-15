import {
  Address,
  GetMinimumBalanceForRentExemptionApi,
  Instruction,
  Rpc,
  TransactionSigner,
} from '@solana/kit';
import { getCreateAccountInstruction } from '@solana-program/system';
import { getVerifyProofInstruction } from '../generic/instructions';
import { ZK_ELGAMAL_PROOF_PROGRAM_ADDRESS, ZkElGamalProofInstruction } from '../generic/programs';
import { BATCHED_RANGE_PROOF_CONTEXT_ACCOUNT_SIZE } from '../constants';
import { ContextStateArgs } from './shared';

export interface VerifyBatchedRangeProofU64Args {
  rpc: Rpc<GetMinimumBalanceForRentExemptionApi>;
  payer: TransactionSigner;
  proofData: Uint8Array;
  contextState?: ContextStateArgs;
  programId?: Address;
}

export async function verifyBatchedRangeProofU64({
  rpc,
  payer,
  proofData,
  contextState,
  programId = ZK_ELGAMAL_PROOF_PROGRAM_ADDRESS,
}: VerifyBatchedRangeProofU64Args): Promise<Instruction[]> {
  const ixs: Instruction[] = [];

  if (contextState) {
    const space = BigInt(BATCHED_RANGE_PROOF_CONTEXT_ACCOUNT_SIZE);
    const lamports = await rpc.getMinimumBalanceForRentExemption(space).send();

    ixs.push(
      getCreateAccountInstruction({
        payer,
        newAccount: contextState.contextAccount,
        lamports,
        space,
        programAddress: programId,
      }),
    );
  }

  const verifyIx = getVerifyProofInstruction(
    {
      discriminator: ZkElGamalProofInstruction.VerifyBatchedRangeProofU64,
      proofData,
      contextState: contextState?.contextAccount.address,
      contextStateAuthority: contextState?.authority,
    },
    { programAddress: programId },
  );

  ixs.push(verifyIx);

  return ixs;
}
