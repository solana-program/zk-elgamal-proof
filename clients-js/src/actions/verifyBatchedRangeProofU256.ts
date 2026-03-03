import {
  Address,
  GetMinimumBalanceForRentExemptionApi,
  Instruction,
  Rpc,
  TransactionSigner,
} from '@solana/kit';
import { getCreateAccountInstruction } from '@solana-program/system';
import { getVerifyProofInstruction, VerifyProofInput } from '../generic/instructions';
import { ZK_ELGAMAL_PROOF_PROGRAM_ADDRESS, ZkElGamalProofInstruction } from '../generic/programs';
import { BATCHED_RANGE_PROOF_CONTEXT_ACCOUNT_SIZE } from '../constants';
import { ContextStateArgs, ProofDataInput } from './shared';

export interface VerifyBatchedRangeProofU256Args {
  rpc: Rpc<GetMinimumBalanceForRentExemptionApi>;
  payer: TransactionSigner;
  proofData: ProofDataInput;
  contextState?: ContextStateArgs;
  programId?: Address;
}

export async function verifyBatchedRangeProofU256({
  rpc,
  payer,
  proofData,
  contextState,
  programId = ZK_ELGAMAL_PROOF_PROGRAM_ADDRESS,
}: VerifyBatchedRangeProofU256Args): Promise<Instruction[]> {
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

  const instructionInput: VerifyProofInput = {
    discriminator: ZkElGamalProofInstruction.VerifyBatchedRangeProofU256,
    contextState: contextState?.contextAccount.address,
    contextStateAuthority: contextState?.authority,
  };

  if (ArrayBuffer.isView(proofData)) {
    instructionInput.proofData = proofData;
  } else {
    instructionInput.proofAccount = proofData.account;
    instructionInput.offset = proofData.offset;
  }

  const verifyIx = getVerifyProofInstruction(instructionInput, { programAddress: programId });

  ixs.push(verifyIx);

  return ixs;
}
