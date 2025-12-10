import {
  Address,
  GetMinimumBalanceForRentExemptionApi,
  Instruction,
  KeyPairSigner,
  Rpc,
  TransactionSigner,
} from '@solana/kit';
import { getCreateAccountInstruction } from '@solana-program/system';
import { getVerifyProofInstruction } from '../generic/instructions';
import { ZK_ELGAMAL_PROOF_PROGRAM_ADDRESS, ZkElGamalProofInstruction } from '../generic/programs';
import { ZERO_CIPHERTEXT_CONTEXT_ACCOUNT_SIZE } from '../constants';

export interface ContextStateArgs {
  contextAccount: KeyPairSigner;
  authority: TransactionSigner | Address;
}

export interface VerifyZeroCiphertextArgs {
  rpc: Rpc<GetMinimumBalanceForRentExemptionApi>;
  payer: TransactionSigner;
  proofData: Uint8Array;
  // Optional: If provided, we create a context account to store the proof
  contextState?: ContextStateArgs;
  programId?: Address;
}

export async function verifyZeroCiphertext({
  rpc,
  payer,
  proofData,
  contextState,
  programId = ZK_ELGAMAL_PROOF_PROGRAM_ADDRESS,
}: VerifyZeroCiphertextArgs): Promise<Instruction[]> {
  const ixs: Instruction[] = [];

  // Handle Context State Creation (if requested)
  if (contextState) {
    const space = BigInt(ZERO_CIPHERTEXT_CONTEXT_ACCOUNT_SIZE);
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

  // Create Verification Instruction
  const verifyIx = getVerifyProofInstruction(
    {
      discriminator: ZkElGamalProofInstruction.VerifyZeroCiphertext,
      proofData,
      // If contextState exists, map it to the instruction inputs
      contextState: contextState?.contextAccount.address,
      contextStateAuthority: contextState?.authority,
    },
    { programAddress: programId },
  );

  ixs.push(verifyIx);

  return ixs;
}
