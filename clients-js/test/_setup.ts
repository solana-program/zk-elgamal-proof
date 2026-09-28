import {
  TransactionMessage,
  Address,
  Commitment,
  Instruction,
  InstructionPlan,
  Rpc,
  RpcSubscriptions,
  SolanaRpcApi,
  SolanaRpcSubscriptionsApi,
  TransactionMessageWithBlockhashLifetime,
  TransactionMessageWithFeePayer,
  TransactionSigner,
  airdropFactory,
  appendTransactionMessageInstructionPlan,
  appendTransactionMessageInstructions,
  assertIsSendableTransaction,
  assertIsTransactionWithBlockhashLifetime,
  createSolanaRpc,
  createSolanaRpcSubscriptions,
  createTransactionMessage,
  generateKeyPairSigner,
  getSignatureFromTransaction,
  lamports,
  pipe,
  sendAndConfirmTransactionFactory,
  setTransactionMessageFeePayer,
  setTransactionMessageFeePayerSigner,
  setTransactionMessageLifetimeUsingBlockhash,
  signTransactionMessageWithSigners,
} from '@solana/kit';
import {
  getCreateRecordInstructionPlan,
  getWriteInstructionPlan,
  RECORD_CHUNK_SIZE_POST_INITIALIZE,
  RECORD_META_DATA_SIZE,
} from '@solana-program/record';

export { RECORD_CHUNK_SIZE_POST_INITIALIZE, RECORD_META_DATA_SIZE };

export type Client = {
  rpc: Rpc<SolanaRpcApi>;
  rpcSubscriptions: RpcSubscriptions<SolanaRpcSubscriptionsApi>;
};

// Flattens an instruction plan into a flat list of instructions by packing it
// into a throwaway transaction message. Sufficient for the small, single-
// transaction record plans these tests build.
export const getInstructionsFromInstructionPlan = (
  plan: InstructionPlan,
  feePayer: Address,
): Instruction[] => {
  const message = pipe(
    createTransactionMessage({ version: 0 }),
    tx => setTransactionMessageFeePayer(feePayer, tx),
    tx => appendTransactionMessageInstructionPlan(plan, tx),
  );
  return [...message.instructions];
};

// Mirrors the shape of record's former `createRecord` helper: generates a fresh
// record keypair and returns the instructions that create and initialize it.
export const createRecord = async (input: {
  rpc: Rpc<SolanaRpcApi>;
  payer: TransactionSigner;
  authority: Address;
  dataLength: bigint;
}): Promise<{ recordKeypair: TransactionSigner; ixs: Instruction[] }> => {
  const recordKeypair = await generateKeyPairSigner();
  const plan = await getCreateRecordInstructionPlan(
    {
      getMinimumBalance: space => input.rpc.getMinimumBalanceForRentExemption(BigInt(space)).send(),
    },
    {
      payer: input.payer,
      newRecord: recordKeypair,
      authority: input.authority,
      dataLength: input.dataLength,
    },
  );
  return { recordKeypair, ixs: getInstructionsFromInstructionPlan(plan, input.payer.address) };
};

// Mirrors the shape of record's former `createWriteInstruction` helper for the
// single-transaction writes these tests perform.
export const createWriteInstruction = (input: {
  recordAccount: Address;
  authority: TransactionSigner;
  offset: bigint;
  data: Uint8Array;
}): Instruction => {
  const plan = getWriteInstructionPlan({
    recordAccount: input.recordAccount,
    authority: input.authority,
    data: input.data,
    offset: Number(input.offset),
  });
  const [instruction] = getInstructionsFromInstructionPlan(plan, input.authority.address);
  return instruction;
};

export const createDefaultSolanaClient = (): Client => {
  const rpc = createSolanaRpc('http://127.0.0.1:8899');
  const rpcSubscriptions = createSolanaRpcSubscriptions('ws://127.0.0.1:8900');
  return { rpc, rpcSubscriptions };
};

export const generateKeyPairSignerWithSol = async (
  client: Client,
  putativeLamports: bigint = 1_000_000_000n,
) => {
  const signer = await generateKeyPairSigner();
  await airdropFactory(client)({
    recipientAddress: signer.address,
    lamports: lamports(putativeLamports),
    commitment: 'confirmed',
  });
  return signer;
};

export const createDefaultTransaction = async (client: Client, feePayer: TransactionSigner) => {
  const { value: latestBlockhash } = await client.rpc.getLatestBlockhash().send();
  return pipe(
    createTransactionMessage({ version: 0 }),
    tx => setTransactionMessageFeePayerSigner(feePayer, tx),
    tx => setTransactionMessageLifetimeUsingBlockhash(latestBlockhash, tx),
  );
};

export const signAndSendTransaction = async (
  client: Client,
  transactionMessage: TransactionMessage &
    TransactionMessageWithFeePayer &
    TransactionMessageWithBlockhashLifetime,
  commitment: Commitment = 'confirmed',
) => {
  const signedTransaction = await signTransactionMessageWithSigners(transactionMessage);
  const signature = getSignatureFromTransaction(signedTransaction);
  assertIsSendableTransaction(signedTransaction);
  assertIsTransactionWithBlockhashLifetime(signedTransaction);
  await sendAndConfirmTransactionFactory(client)(signedTransaction, {
    commitment,
  });
  return signature;
};

export const sendAndConfirmInstructions = async (
  client: Client,
  payer: TransactionSigner,
  instructions: Instruction[],
) => {
  const signature = await pipe(
    await createDefaultTransaction(client, payer),
    tx => appendTransactionMessageInstructions(instructions, tx),
    tx => signAndSendTransaction(client, tx),
  );
  return signature;
};
