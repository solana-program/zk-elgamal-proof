import { Address, HasAddress, KeyPairSigner } from '@solana/kit';

export type ProofDataInput = Uint8Array | { account: Address | HasAddress; offset: number };

export interface ContextStateArgs {
  contextAccount: KeyPairSigner;
  authority: Address | HasAddress;
}
