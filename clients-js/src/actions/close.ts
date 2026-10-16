import { Address, HasAddress, Instruction, TransactionSigner } from '@solana/kit';
import { getCloseContextStateInstruction } from '../generic/instructions';
import { ZK_ELGAMAL_PROOF_PROGRAM_ADDRESS } from '../generic/programs';
import { toAddress } from './internal';

export interface CloseContextStateArgs {
  contextState: Address | HasAddress;
  authority: TransactionSigner;
  destination: Address | HasAddress;
  programId?: Address | HasAddress;
}

export function closeContextStateProof({
  contextState,
  authority,
  destination,
  programId = ZK_ELGAMAL_PROOF_PROGRAM_ADDRESS,
}: CloseContextStateArgs): Instruction {
  return getCloseContextStateInstruction(
    {
      contextState: toAddress(contextState),
      authority,
      destination: toAddress(destination),
    },
    { programAddress: toAddress(programId) },
  );
}
