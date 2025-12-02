import {
  combineCodec,
  getU32Decoder,
  getU32Encoder,
  getU8Decoder,
  getU8Encoder,
  type AccountMeta,
  type AccountSignerMeta,
  type Address,
  type Codec,
  type Decoder,
  type Encoder,
  type Instruction,
  type InstructionWithAccounts,
  type InstructionWithData,
  type ReadonlyAccount,
  type ReadonlyUint8Array,
  type WritableAccount,
} from '@solana/kit';
import { ZK_ELGAMAL_PROOF_PROGRAM_ADDRESS } from '../programs';
import { getAccountMetaFactory } from '../shared';

// --- Data Management ---

export interface VerifyProofInstructionData {
  discriminator: number;
  // If proof is in an account, this is the offset.
  // If proof is in instruction data, this is undefined (and we use proofData).
  offset?: number;
  proofData?: ReadonlyUint8Array;
}

export interface VerifyProofInstructionDataArgs {
  discriminator: number;
  offset?: number;
  proofData?: ReadonlyUint8Array;
}

/**
 * Universal encoder for all verification instructions.
 * Encodes: [discriminator, u32 offset] OR [discriminator, ...proofBytes]
 */
export function getVerifyProofInstructionDataEncoder(): Encoder<VerifyProofInstructionDataArgs> {
  const getSizeFromValue = (value: VerifyProofInstructionDataArgs) => {
    if (value.offset !== undefined) {
      return 1 + 4; // discriminator(u8) + offset(u32)
    }
    return 1 + (value.proofData?.length ?? 0);
  };

  const write = (value: VerifyProofInstructionDataArgs, bytes: Uint8Array, offset: number) => {
    offset = getU8Encoder().write(value.discriminator, bytes, offset);
    if (value.offset !== undefined) {
      offset = getU32Encoder().write(value.offset, bytes, offset);
    } else if (value.proofData !== undefined) {
      bytes.set(value.proofData, offset);
      offset += value.proofData.length;
    }
    return offset;
  };

  return {
    getSizeFromValue,
    write,
    encode: (value: VerifyProofInstructionDataArgs) => {
      const size = getSizeFromValue(value);
      const bytes = new Uint8Array(size);
      write(value, bytes, 0);
      return bytes;
    },
  };
}

export function getVerifyProofInstructionDataDecoder(): Decoder<VerifyProofInstructionData> {
  const read = (
    bytes: ReadonlyUint8Array,
    offset: number,
  ): [VerifyProofInstructionData, number] => {
    const [discriminator, offsetAfterDisc] = getU8Decoder().read(bytes, offset);
    offset = offsetAfterDisc;

    // If exactly 5 bytes total (1 disc + 4 offset), treat as offset mode.
    // All ZK proofs in the program are required to be at least 32 bytes.
    if (bytes.length === 5) {
      const [offsetValue, newOffset] = getU32Decoder().read(bytes, offset);
      return [{ discriminator, offset: offsetValue }, newOffset];
    }

    // Otherwise, everything else is proof data.
    const proofData = bytes.slice(offset);
    return [{ discriminator, proofData }, bytes.length];
  };

  return {
    read,
    decode: (bytes: ReadonlyUint8Array, offset = 0) => {
      return read(bytes, offset)[0];
    },
  };
}

export function getVerifyProofInstructionDataCodec(): Codec<
  VerifyProofInstructionDataArgs,
  VerifyProofInstructionData
> {
  return combineCodec(
    getVerifyProofInstructionDataEncoder(),
    getVerifyProofInstructionDataDecoder(),
  );
}

export type VerifyProofInstruction<
  TProgram extends string = typeof ZK_ELGAMAL_PROOF_PROGRAM_ADDRESS,
  TAccountContextState extends string | AccountMeta = string,
  TAccountContextStateAuthority extends string | AccountMeta = string,
  TAccountProofAccount extends string | AccountMeta = string,
  TRemainingAccounts extends readonly AccountMeta[] = [],
> = Instruction<TProgram> &
  InstructionWithData<ReadonlyUint8Array> &
  InstructionWithAccounts<
    [
      // 1. Proof Account (First, if present)
      TAccountProofAccount extends string
        ? ReadonlyAccount<TAccountProofAccount>
        : TAccountProofAccount,
      // 2. Context State
      TAccountContextState extends string
        ? WritableAccount<TAccountContextState>
        : TAccountContextState,
      // 3. Context State Authority
      TAccountContextStateAuthority extends string
        ? ReadonlyAccount<TAccountContextStateAuthority> &
            AccountSignerMeta<TAccountContextStateAuthority>
        : TAccountContextStateAuthority,
      ...TRemainingAccounts,
    ]
  >;

export interface VerifyProofInput<
  TAccountProofAccount extends string = string,
  TAccountContextState extends string = string,
  TAccountContextStateAuthority extends string = string,
> {
  discriminator: number;

  // Proof Account (Optional)
  proofAccount?: Address<TAccountProofAccount>;

  // Context State Accounts (Optional)
  contextState?: Address<TAccountContextState>;
  contextStateAuthority?: Address<TAccountContextStateAuthority>;

  // Proof Source (Mutually Exclusive)
  offset?: number;
  proofData?: ReadonlyUint8Array;
}

export function getVerifyProofInstruction<
  TAccountContextState extends string,
  TAccountContextStateAuthority extends string,
  TAccountProofAccount extends string,
  TProgramAddress extends Address = typeof ZK_ELGAMAL_PROOF_PROGRAM_ADDRESS,
>(
  input: VerifyProofInput<
    TAccountContextState,
    TAccountContextStateAuthority,
    TAccountProofAccount
  >,
  config?: { programAddress?: TProgramAddress },
): VerifyProofInstruction<
  TProgramAddress,
  TAccountContextState,
  TAccountContextStateAuthority,
  TAccountProofAccount
> {
  const programAddress = config?.programAddress ?? ZK_ELGAMAL_PROOF_PROGRAM_ADDRESS;

  const originalAccounts = {
    contextState: {
      value: input.contextState ?? null,
      isWritable: true,
    },
    contextStateAuthority: {
      value: input.contextStateAuthority ?? null,
      isWritable: false,
    },
    proofAccount: {
      value: input.proofAccount ?? null,
      isWritable: false,
    },
  };

  const getAccountMeta = getAccountMetaFactory(programAddress, 'programId');
  const accounts: (AccountMeta | AccountSignerMeta)[] = [];

  if (input.proofAccount) {
    // Case A: Proof in Account
    // Accounts: [ProofAccount, (Context, Auth)?]
    const proofMeta = getAccountMeta(originalAccounts.proofAccount);
    if (proofMeta) {
      accounts.push(proofMeta);
    }
    if (input.contextState) {
      const ctxMeta = getAccountMeta(originalAccounts.contextState);
      const authMeta = getAccountMeta(originalAccounts.contextStateAuthority);

      if (ctxMeta) accounts.push(ctxMeta);
      if (authMeta) accounts.push(authMeta);
    }
  } else {
    // Case B: Proof in Instruction Data
    // Accounts: [(Context, Auth)?]
    if (input.contextState) {
      const ctxMeta = getAccountMeta(originalAccounts.contextState);
      const authMeta = getAccountMeta(originalAccounts.contextStateAuthority);

      if (ctxMeta) accounts.push(ctxMeta);
      if (authMeta) accounts.push(authMeta);
    }
  }

  const args: VerifyProofInstructionDataArgs = {
    discriminator: input.discriminator,
  };

  if (input.proofAccount) {
    args.offset = input.offset ?? 0;
  } else {
    if (!input.proofData) {
      throw new Error('proofData is required when proofAccount is not provided');
    }
    args.proofData = input.proofData;
  }

  return {
    accounts,
    programAddress,
    data: getVerifyProofInstructionDataEncoder().encode(args),
  } as VerifyProofInstruction<
    TProgramAddress,
    TAccountContextState,
    TAccountContextStateAuthority,
    TAccountProofAccount
  >;
}
