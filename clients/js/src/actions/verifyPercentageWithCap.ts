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
import { PERCENTAGE_WITH_CAP_CONTEXT_ACCOUNT_SIZE } from '../constants';
import { ContextStateArgs, ProofDataInput } from './shared';

export interface VerifyPercentageWithCapArgs {
  rpc: Rpc<GetMinimumBalanceForRentExemptionApi>;
  payer: TransactionSigner;
  proofData: ProofDataInput;
  // Optional: If provided, we create a context account to store the proof
  contextState?: ContextStateArgs;
  programId?: Address;
}

/**
 * Verifies a percentage-with-cap proof.
 *
 * A percentage-with-cap proof certifies that a transfer amount is within a certain percentage
 * of a base amount, capped at a maximum value.
 *
 * This function creates a transaction that:
 * 1. Optionally creates a context state account if `contextState` is provided.
 * 2. Calls the `VerifyPercentageWithCap` instruction on the ZK ElGamal Proof program.
 */
export async function verifyPercentageWithCap({
  rpc,
  payer,
  proofData,
  contextState,
  programId = ZK_ELGAMAL_PROOF_PROGRAM_ADDRESS,
}: VerifyPercentageWithCapArgs): Promise<Instruction[]> {
  const ixs: Instruction[] = [];

  // Handle Context State Creation (if requested)
  if (contextState) {
    const space = BigInt(PERCENTAGE_WITH_CAP_CONTEXT_ACCOUNT_SIZE);
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
    discriminator: ZkElGamalProofInstruction.VerifyPercentageWithCap,
    contextState: contextState?.contextAccount.address,
    contextStateAuthority: contextState?.authority,
  };

  if (ArrayBuffer.isView(proofData)) {
    // Proof is raw bytes
    instructionInput.proofData = proofData;
  } else {
    // Proof is in a record account
    instructionInput.proofAccount = proofData.account;
    instructionInput.offset = proofData.offset;
  }

  // Create Verification Instruction
  const verifyIx = getVerifyProofInstruction(instructionInput, { programAddress: programId });

  ixs.push(verifyIx);

  return ixs;
}
