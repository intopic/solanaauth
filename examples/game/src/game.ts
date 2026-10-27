/** Instruksionet e lojës demo (`programs/demo-game`). */
import { Buffer } from "buffer";
import { PublicKey, SystemProgram, TransactionInstruction } from "@solana/web3.js";

export function playerState(gameProgram: PublicKey, player: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync([new TextEncoder().encode("player"), player.toBytes()], gameProgram)[0];
}

export function join(gameProgram: PublicKey, player: PublicKey): TransactionInstruction {
  return new TransactionInstruction({
    programId: gameProgram,
    data: Buffer.from([0]),
    keys: [
      { pubkey: player, isSigner: true, isWritable: true },
      { pubkey: playerState(gameProgram, player), isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
  });
}

export function play(gameProgram: PublicKey, player: PublicKey): TransactionInstruction {
  return new TransactionInstruction({
    programId: gameProgram,
    data: Buffer.from([1]),
    keys: [
      { pubkey: player, isSigner: true, isWritable: false },
      { pubkey: playerState(gameProgram, player), isSigner: false, isWritable: true },
    ],
  });
}

export function decodeScore(data: Uint8Array): { score: bigint; lastPlay: bigint } {
  const v = new DataView(data.buffer, data.byteOffset, data.byteLength);
  return { score: v.getBigUint64(0, true), lastPlay: v.getBigInt64(8, true) };
}
