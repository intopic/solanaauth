// Server me burim me pagesë (x402) që është edhe facilitator: verifikon pagesën, e nënshkruan si
// fee payer dhe e dërgon. Pranon vetëm një `execute` të solanaauth me një `TransferChecked` të saktë.
import { PublicKey } from "@solana/web3.js";
import { decodeX402Payment } from "@solanaauth/agent";

const TOKEN = new PublicKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
const ATA = new PublicKey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
const COMPUTE_BUDGET = new PublicKey("ComputeBudget111111111111111111111111111111");
const ata = (owner, mint) => PublicKey.findProgramAddressSync([owner.toBuffer(), TOKEN.toBuffer(), mint.toBuffer()], ATA)[0];

/** Instruksionet e brendshme të `execute` (kodimi i `executeParts`). */
export function innerInstructions(data, keys) {
  let o = 2;
  if (data[1] & 1) o += 2 + (data[o] | (data[o + 1] << 8));
  const n = data[o++];
  const out = [];
  for (let i = 0; i < n; i++) {
    const program = keys[data[o++]];
    const nAcc = data[o++];
    const accounts = [];
    for (let k = 0; k < nAcc; k++) {
      accounts.push(keys[data[o]]);
      o += 2;
    }
    const len = data[o] | (data[o + 1] << 8);
    o += 2;
    out.push({ program, accounts, data: data.subarray(o, o + len) });
    o += len;
  }
  return out;
}

/**
 * @param o.chain { send(raw): Promise<string> } — simulimi bëhet nga RPC/LiteSVM gjatë dërgimit
 * @param o.feePayer Keypair i facilitator-it (vetëm tarifat)
 */
export function x402Handler(o) {
  const payToAta = ata(o.payTo, o.mint);
  const requirements = (resource) => ({
    scheme: "exact",
    network: o.network,
    maxAmountRequired: o.price.toString(),
    asset: o.mint.toBase58(),
    payTo: o.payTo.toBase58(),
    resource,
    description: o.description,
    extra: { feePayer: o.feePayer.publicKey.toBase58(), decimals: o.decimals },
  });

  function verify(tx) {
    if (!tx.feePayer?.equals(o.feePayer.publicKey)) throw new Error("fee payer i gabuar");
    const main = tx.instructions.filter((ix) => !ix.programId.equals(COMPUTE_BUDGET));
    if (main.length !== 1 || !main[0].programId.equals(o.programId) || main[0].data[0] !== 7) throw new Error("pritet një `execute` i solanaauth");
    const ix = main[0];
    if (ix.keys.some((k) => k.pubkey.equals(o.feePayer.publicKey))) throw new Error("fee payer-i s'mund të jetë llogari");
    const inner = innerInstructions(ix.data, ix.keys.map((k) => k.pubkey));
    if (inner.length !== 1 || !inner[0].program.equals(TOKEN) || inner[0].data[0] !== 12) throw new Error("pritet një TransferChecked");
    const t = inner[0];
    const amount = Buffer.from(t.data).readBigUInt64LE(1);
    if (!t.accounts[1].equals(o.mint) || !t.accounts[2].equals(payToAta)) throw new Error("mint ose marrës i gabuar");
    if (amount < o.price) throw new Error("shumë e pamjaftueshme");
    return amount;
  }

  return async (req, res) => {
    const url = new URL(req.url, "http://x");
    const header = req.headers["x-payment"];
    const reply = (status, body, h = {}) => res.writeHead(status, { "content-type": "application/json", ...h }).end(JSON.stringify(body));
    if (!header) return reply(402, { x402Version: 1, error: "pagesa kërkohet", accepts: [requirements(url.pathname)] });
    try {
      const { transaction: tx } = decodeX402Payment(String(header));
      const amount = verify(tx);
      tx.partialSign(o.feePayer);
      const signature = await o.chain.send(tx.serialize());
      const receipt = Buffer.from(JSON.stringify({ success: true, transaction: signature, network: o.network })).toString("base64");
      return reply(200, await o.serve(url.pathname, amount), { "x-payment-response": receipt });
    } catch (e) {
      return reply(402, { x402Version: 1, error: e.message, accepts: [requirements(url.pathname)] });
    }
  };
}
