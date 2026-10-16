import { Address, HasAddress } from '@solana/kit';

/**
 * Unwraps an address input that may be either a plain {@link Address} or an
 * address-bearing object (see {@link HasAddress}) into a plain {@link Address}.
 */
export function toAddress<TAddress extends string>(
  input: Address<TAddress> | HasAddress<TAddress>,
): Address<TAddress> {
  return typeof input === 'string' ? input : input.address;
}
