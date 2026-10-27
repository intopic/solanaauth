import { ComputeBudgetProgram, TransactionInstruction } from "@solana/web3.js";

/** Validate client-supplied budget instructions before a sponsor signs them. */
export function validateComputeBudget(instructions: TransactionInstruction[], maxPrice: bigint, maxPriorityLamports: bigint): void {
  const seen = new Set<number>();
  // Without an explicit limit the runtime budget depends on instruction count. Use its
  // maximum rather than underestimating a batch's fee as one 200k-CU instruction.
  let units = 1_400_000n;
  let price = 0n;
  for (const ix of instructions) {
    if (!ix.programId.equals(ComputeBudgetProgram.programId)) continue;
    const op = ix.data[0];
    if (ix.keys.length || seen.has(op)) throw new Error("invalid or duplicate compute budget instruction");
    seen.add(op);
    if (op === 3 && ix.data.length === 9) {
      price = ix.data.readBigUInt64LE(1);
      if (price > maxPrice) throw new Error("priority fee price exceeds limit");
    } else if ([1, 2, 4].includes(op) && ix.data.length === 5) {
      const n = ix.data.readUInt32LE(1);
      if (op === 2) {
        if (n === 0 || n > 1_400_000) throw new Error("invalid compute unit limit");
        units = BigInt(n);
      } else if ((op === 1 && (n < 32_768 || n > 262_144 || n % 1024 !== 0)) || (op === 4 && (n === 0 || n > 67_108_864))) {
        throw new Error("invalid compute budget limit");
      }
    } else throw new Error("unsupported compute budget instruction");
  }
  if ((units * price + 999_999n) / 1_000_000n > maxPriorityLamports) throw new Error("total priority fee exceeds limit");
}
