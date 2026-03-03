import { type Address } from '@solana/kit';

export const ZK_ELGAMAL_PROOF_PROGRAM_ADDRESS =
  'ZkE1Gama1Proof11111111111111111111111111111' as Address<'ZkE1Gama1Proof11111111111111111111111111111'>;

export enum ZkElGamalProofAccount {
  ContextState = 0,
}

export enum ZkElGamalProofInstruction {
  CloseContextState = 0,
  VerifyZeroCiphertext = 1,
  VerifyCiphertextCiphertextEquality = 2,
  VerifyCiphertextCommitmentEquality = 3,
  VerifyPubkeyValidity = 4,
  VerifyPercentageWithCap = 5,
  VerifyBatchedRangeProofU64 = 6,
  VerifyBatchedRangeProofU128 = 7,
  VerifyBatchedRangeProofU256 = 8,
  VerifyGroupedCiphertext2HandlesValidity = 9,
  VerifyBatchedGroupedCiphertext2HandlesValidity = 10,
  VerifyGroupedCiphertext3HandlesValidity = 11,
  VerifyBatchedGroupedCiphertext3HandlesValidity = 12,
}
