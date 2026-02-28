import { Address, Instruction, TransactionSigner } from '@solana/kit';
import { getCloseContextStateInstruction } from '../generic/instructions';
import { ZK_ELGAMAL_PROOF_PROGRAM_ADDRESS } from '../generic/programs';

export interface CloseContextStateArgs {
  contextState: Address;
  authority: TransactionSigner;
  destination: Address;
  programId?: Address;
}

export function closeContextStateProof({
  contextState,
  authority,
  destination,
  programId = ZK_ELGAMAL_PROOF_PROGRAM_ADDRESS,
}: CloseContextStateArgs): Instruction {
  return getCloseContextStateInstruction(
    {
      contextState,
      authority,
      destination,
    },
    { programAddress: programId },
  );
}
