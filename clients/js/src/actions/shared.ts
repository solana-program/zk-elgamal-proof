import { Address, KeyPairSigner } from '@solana/kit';

export type ProofDataInput = Uint8Array | { account: Address; offset: number };

export interface ContextStateArgs {
  contextAccount: KeyPairSigner;
  authority: Address;
}
