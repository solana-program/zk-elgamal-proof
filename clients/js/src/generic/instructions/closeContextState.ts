import {
  combineCodec,
  getStructDecoder,
  getStructEncoder,
  getU8Decoder,
  getU8Encoder,
  transformEncoder,
  type AccountMeta,
  type AccountSignerMeta,
  type Address,
  type FixedSizeCodec,
  type FixedSizeDecoder,
  type FixedSizeEncoder,
  type Instruction,
  type InstructionWithAccounts,
  type InstructionWithData,
  type ReadonlySignerAccount,
  type ReadonlyUint8Array,
  type TransactionSigner,
  type WritableAccount,
} from '@solana/kit';
import { ZK_ELGAMAL_PROOF_PROGRAM_ADDRESS } from '../programs';
import { getAccountMetaFactory, type ResolvedAccount } from '../shared';

export const CLOSE_CONTEXT_STATE_DISCRIMINATOR = 0;

export function getCloseContextStateDiscriminatorBytes() {
  return getU8Encoder().encode(CLOSE_CONTEXT_STATE_DISCRIMINATOR);
}

export type CloseContextStateInstruction<
  TProgram extends string = typeof ZK_ELGAMAL_PROOF_PROGRAM_ADDRESS,
  TAccountContextState extends string | AccountMeta<string> = string,
  TAccountDestination extends string | AccountMeta<string> = string,
  TAccountAuthority extends string | AccountMeta<string> = string,
  TRemainingAccounts extends readonly AccountMeta<string>[] = [],
> = Instruction<TProgram> &
  InstructionWithData<ReadonlyUint8Array> &
  InstructionWithAccounts<
    [
      TAccountContextState extends string
        ? WritableAccount<TAccountContextState>
        : TAccountContextState,
      TAccountDestination extends string
        ? WritableAccount<TAccountDestination>
        : TAccountDestination,
      TAccountAuthority extends string
        ? ReadonlySignerAccount<TAccountAuthority> &
            AccountSignerMeta<TAccountAuthority>
        : TAccountAuthority,
      ...TRemainingAccounts,
    ]
  >;

export type CloseContextStateInstructionData = { discriminator: number };

export type CloseContextStateInstructionDataArgs = {};

export function getCloseContextStateInstructionDataEncoder(): FixedSizeEncoder<CloseContextStateInstructionDataArgs> {
  return transformEncoder(
    getStructEncoder([['discriminator', getU8Encoder()]]),
    (value) => ({
      ...value,
      discriminator: CLOSE_CONTEXT_STATE_DISCRIMINATOR,
    })
  );
}

export function getCloseContextStateInstructionDataDecoder(): FixedSizeDecoder<CloseContextStateInstructionData> {
  return getStructDecoder([['discriminator', getU8Decoder()]]);
}

export function getCloseContextStateInstructionDataCodec(): FixedSizeCodec<
  CloseContextStateInstructionDataArgs,
  CloseContextStateInstructionData
> {
  return combineCodec(
    getCloseContextStateInstructionDataEncoder(),
    getCloseContextStateInstructionDataDecoder()
  );
}

export type CloseContextStateInput<
  TAccountContextState extends string = string,
  TAccountDestination extends string = string,
  TAccountAuthority extends string = string,
> = {
  contextState: Address<TAccountContextState>;
  destination: Address<TAccountDestination>;
  authority: TransactionSigner<TAccountAuthority>;
};

export function getCloseContextStateInstruction<
  TAccountContextState extends string,
  TAccountDestination extends string,
  TAccountAuthority extends string,
  TProgramAddress extends Address = typeof ZK_ELGAMAL_PROOF_PROGRAM_ADDRESS,
>(
  input: CloseContextStateInput<
    TAccountContextState,
    TAccountDestination,
    TAccountAuthority
  >,
  config?: { programAddress?: TProgramAddress }
): CloseContextStateInstruction<
  TProgramAddress,
  TAccountContextState,
  TAccountDestination,
  TAccountAuthority
> {
  // Program address.
  const programAddress =
    config?.programAddress ?? ZK_ELGAMAL_PROOF_PROGRAM_ADDRESS;

  // Original accounts.
  const originalAccounts = {
    contextState: { value: input.contextState ?? null, isWritable: true },
    destination: { value: input.destination ?? null, isWritable: true },
    authority: { value: input.authority ?? null, isWritable: false },
  };
  const accounts = originalAccounts as Record<
    keyof typeof originalAccounts,
    ResolvedAccount
  >;

  const getAccountMeta = getAccountMetaFactory(programAddress, 'programId');
  return Object.freeze({
    accounts: [
      getAccountMeta(accounts.contextState),
      getAccountMeta(accounts.destination),
      getAccountMeta(accounts.authority),
    ],
    data: getCloseContextStateInstructionDataEncoder().encode({}),
    programAddress,
  } as CloseContextStateInstruction<
    TProgramAddress,
    TAccountContextState,
    TAccountDestination,
    TAccountAuthority
  >);
}

export type ParsedCloseContextStateInstruction<
  TProgram extends string = typeof ZK_ELGAMAL_PROOF_PROGRAM_ADDRESS,
  TAccountMetas extends readonly AccountMeta[] = readonly AccountMeta[],
> = {
  programAddress: Address<TProgram>;
  accounts: {
    contextState: TAccountMetas[0];
    destination: TAccountMetas[1];
    authority: TAccountMetas[2];
  };
  data: CloseContextStateInstructionData;
};

export function parseCloseContextStateInstruction<
  TProgram extends string,
  TAccountMetas extends readonly AccountMeta[],
>(
  instruction: Instruction<TProgram> &
    InstructionWithAccounts<TAccountMetas> &
    InstructionWithData<ReadonlyUint8Array>
): ParsedCloseContextStateInstruction<TProgram, TAccountMetas> {
  if (instruction.accounts.length < 3) {
    throw new Error('Not enough accounts');
  }
  let accountIndex = 0;
  const getNextAccount = () => {
    const accountMeta = (instruction.accounts as TAccountMetas)[accountIndex]!;
    accountIndex += 1;
    return accountMeta;
  };
  return {
    programAddress: instruction.programAddress,
    accounts: {
      contextState: getNextAccount(),
      destination: getNextAccount(),
      authority: getNextAccount(),
    },
    data: getCloseContextStateInstructionDataDecoder().decode(instruction.data),
  };
}
