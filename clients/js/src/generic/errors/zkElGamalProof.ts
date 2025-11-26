import {
  isProgramError,
  type Address,
  type SOLANA_ERROR__INSTRUCTION_ERROR__CUSTOM,
  type SolanaError,
} from '@solana/kit';
import { ZK_ELGAMAL_PROOF_PROGRAM_ADDRESS } from '../programs';

// Mapped from zk_elgamal_proof_program/errors.rs
export const ZK_ELGAMAL_PROOF_ERROR__RANGE_PROOF_VERIFICATION_FAILED = 0;
export const ZK_ELGAMAL_PROOF_ERROR__SIGMA_PROOF_VERIFICATION_FAILED = 1;
export const ZK_ELGAMAL_PROOF_ERROR__ELGAMAL_ERROR = 2;
export const ZK_ELGAMAL_PROOF_ERROR__INVALID_PROOF_CONTEXT = 3;
export const ZK_ELGAMAL_PROOF_ERROR__ILLEGAL_COMMITMENT_LENGTH = 4;
export const ZK_ELGAMAL_PROOF_ERROR__ILLEGAL_AMOUNT_BIT_LENGTH = 5;

export type ZkElGamalProofError =
  | typeof ZK_ELGAMAL_PROOF_ERROR__RANGE_PROOF_VERIFICATION_FAILED
  | typeof ZK_ELGAMAL_PROOF_ERROR__SIGMA_PROOF_VERIFICATION_FAILED
  | typeof ZK_ELGAMAL_PROOF_ERROR__ELGAMAL_ERROR
  | typeof ZK_ELGAMAL_PROOF_ERROR__INVALID_PROOF_CONTEXT
  | typeof ZK_ELGAMAL_PROOF_ERROR__ILLEGAL_COMMITMENT_LENGTH
  | typeof ZK_ELGAMAL_PROOF_ERROR__ILLEGAL_AMOUNT_BIT_LENGTH;

let zkElgamalProofErrorMessages:
  | Record<ZkElGamalProofError, string>
  | undefined;

if (process.env.NODE_ENV !== 'production') {
  zkElgamalProofErrorMessages = {
    [ZK_ELGAMAL_PROOF_ERROR__RANGE_PROOF_VERIFICATION_FAILED]: `Range proof verification failed`,
    [ZK_ELGAMAL_PROOF_ERROR__SIGMA_PROOF_VERIFICATION_FAILED]: `Sigma proof verification failed`,
    [ZK_ELGAMAL_PROOF_ERROR__ELGAMAL_ERROR]: `ElGamal ciphertext or public key error`,
    [ZK_ELGAMAL_PROOF_ERROR__INVALID_PROOF_CONTEXT]: `Invalid proof context`,
    [ZK_ELGAMAL_PROOF_ERROR__ILLEGAL_COMMITMENT_LENGTH]: `Illegal commitment length`,
    [ZK_ELGAMAL_PROOF_ERROR__ILLEGAL_AMOUNT_BIT_LENGTH]: `Illegal amount bit length`,
  };
}

export function getZkElgamalProofErrorMessage(
  code: ZkElGamalProofError
): string {
  if (process.env.NODE_ENV !== 'production') {
    return (zkElgamalProofErrorMessages as Record<ZkElGamalProofError, string>)[
      code
    ];
  }

  return 'Error message not available in production bundles.';
}

export function isZkElgamalProofError<
  TProgramErrorCode extends ZkElGamalProofError,
>(
  error: unknown,
  transactionMessage: {
    instructions: Record<number, { programAddress: Address }>;
  },
  code?: TProgramErrorCode
): error is SolanaError<typeof SOLANA_ERROR__INSTRUCTION_ERROR__CUSTOM> &
  Readonly<{ context: Readonly<{ code: TProgramErrorCode }> }> {
  return isProgramError<TProgramErrorCode>(
    error,
    transactionMessage,
    ZK_ELGAMAL_PROOF_PROGRAM_ADDRESS,
    code
  );
}
