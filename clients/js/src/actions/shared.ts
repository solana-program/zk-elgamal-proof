import { Address, KeyPairSigner, TransactionSigner } from '@solana/kit';

export interface ContextStateArgs {
  contextAccount: KeyPairSigner;
  authority: TransactionSigner | Address;
}
