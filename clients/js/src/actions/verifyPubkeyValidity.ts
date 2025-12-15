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
import { PUBKEY_VALIDITY_CONTEXT_ACCOUNT_SIZE } from '../constants';
import { ContextStateArgs } from './shared';

export interface VerifyPubkeyValidityArgs {
  rpc: Rpc<GetMinimumBalanceForRentExemptionApi>;
  payer: TransactionSigner;
  proofData: Uint8Array;
  // Optional: If provided, we create a context account to store the proof
  contextState?: ContextStateArgs;
  programId?: Address;
}

/**
 * Verifies that an ElGamal public key is valid (i.e., the prover knows the corresponding secret key).
 *
 * This function creates a transaction that:
 * 1. Optionally creates a context state account if `contextState` is provided.
 * 2. Calls the `VerifyPubkeyValidity` instruction on the ZK ElGamal Proof program.
 */
export async function verifyPubkeyValidity({
  rpc,
  payer,
  proofData,
  contextState,
  programId = ZK_ELGAMAL_PROOF_PROGRAM_ADDRESS,
}: VerifyPubkeyValidityArgs): Promise<Instruction[]> {
  const ixs: Instruction[] = [];

  // Handle Context State Creation (if requested)
  if (contextState) {
    const space = BigInt(PUBKEY_VALIDITY_CONTEXT_ACCOUNT_SIZE);
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
      discriminator: ZkElGamalProofInstruction.VerifyPubkeyValidity, // Discriminator 4
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
