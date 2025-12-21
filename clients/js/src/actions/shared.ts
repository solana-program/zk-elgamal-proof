import { Address, KeyPairSigner } from '@solana/kit';

export interface ContextStateArgs {
  contextAccount: KeyPairSigner;
  authority: Address;
}
