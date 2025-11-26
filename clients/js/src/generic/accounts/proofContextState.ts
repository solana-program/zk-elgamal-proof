import {
  assertAccountExists,
  decodeAccount,
  fetchEncodedAccount,
  getAddressDecoder,
  getU8Decoder,
  type Account,
  type Address,
  type Decoder,
  type EncodedAccount,
  type FetchAccountConfig,
  type MaybeAccount,
  type MaybeEncodedAccount,
  type ReadonlyUint8Array,
} from '@solana/kit';

/**
 * Enum matching the Rust `ProofType` enum.
 * This distinguishes what kind of proof data is stored in the account.
 */
export enum ProofType {
  Uninitialized = 0,
  ZeroCiphertext = 1,
  CiphertextCiphertextEquality = 2,
  CiphertextCommitmentEquality = 3,
  PubkeyValidity = 4,
  PercentageWithCap = 5,
  BatchedRangeProofU64 = 6,
  BatchedRangeProofU128 = 7,
  BatchedRangeProofU256 = 8,
  GroupedCiphertext2HandlesValidity = 9,
  BatchedGroupedCiphertext2HandlesValidity = 10,
  GroupedCiphertext3HandlesValidity = 11,
  BatchedGroupedCiphertext3HandlesValidity = 12,
}

export type ProofContextState = {
  contextStateAuthority: Address;
  proofType: ProofType;
  /** The raw bytes of the proof context. Can be decoded further based on proofType. */
  proofContext: ReadonlyUint8Array;
};

/**
 * Custom decoder for ProofContextState.
 * It reads the fixed header (33 bytes) and captures the remaining bytes as context.
 */
export function getProofContextStateDecoder(): Decoder<ProofContextState> {
  const read = (
    bytes: ReadonlyUint8Array,
    offset = 0
  ): [ProofContextState, number] => {
    const [contextStateAuthority, offsetAuth] = getAddressDecoder().read(
      bytes,
      offset
    );

    const [proofTypeRaw, offsetType] = getU8Decoder().read(bytes, offsetAuth);
    const proofContext = bytes.slice(offsetType);

    return [
      {
        contextStateAuthority,
        proofType: proofTypeRaw as ProofType,
        proofContext,
      },
      bytes.length,
    ];
  };

  return {
    read,
    decode: (bytes: ReadonlyUint8Array, offset = 0) => read(bytes, offset)[0],
  };
}

export function decodeProofContextState<TAddress extends string = string>(
  encodedAccount: EncodedAccount<TAddress>
): Account<ProofContextState, TAddress>;
export function decodeProofContextState<TAddress extends string = string>(
  encodedAccount: MaybeEncodedAccount<TAddress>
): MaybeAccount<ProofContextState, TAddress>;
export function decodeProofContextState<TAddress extends string = string>(
  encodedAccount: EncodedAccount<TAddress> | MaybeEncodedAccount<TAddress>
):
  | Account<ProofContextState, TAddress>
  | MaybeAccount<ProofContextState, TAddress> {
  return decodeAccount(
    encodedAccount as MaybeEncodedAccount<TAddress>,
    getProofContextStateDecoder()
  );
}

export async function fetchProofContextState<TAddress extends string = string>(
  rpc: Parameters<typeof fetchEncodedAccount>[0],
  address: Address<TAddress>,
  config?: FetchAccountConfig
): Promise<Account<ProofContextState, TAddress>> {
  const maybeAccount = await fetchEncodedAccount(rpc, address, config);
  const account = decodeProofContextState(maybeAccount);
  assertAccountExists(account);
  return account;
}

export async function fetchMaybeProofContextState<
  TAddress extends string = string,
>(
  rpc: Parameters<typeof fetchEncodedAccount>[0],
  address: Address<TAddress>,
  config?: FetchAccountConfig
): Promise<MaybeAccount<ProofContextState, TAddress>> {
  const maybeAccount = await fetchEncodedAccount(rpc, address, config);
  return decodeProofContextState(maybeAccount);
}
