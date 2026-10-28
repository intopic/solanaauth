import { PublicKey } from "@solana/web3.js";
import { delegationPolicy, encodePolicy, Policy } from "./instructions.js";

/** Public approval payload. It never contains an OAuth token, proof or private key. */
export function policyToJson(policy: Policy): Record<string, unknown> {
  const p = delegationPolicy(policy);
  encodePolicy(p);
  return { ...p, allowedPrograms: p.allowedPrograms?.map(k => k.toBase58()), limits: p.limits?.map(l => ({ ...l, mint: l.mint.toBase58(), amount: l.amount?.toString(), maxPerExecute: l.maxPerExecute?.toString() })) };
}

const object = (value: unknown): Record<string, any> => {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("policy must be an object");
  return value as Record<string, any>;
};
const keys = (o: Record<string, unknown>, allowed: string[]) => {
  if (Object.keys(o).some(k => !allowed.includes(k))) throw new Error("unsupported policy field");
};
const amount = (v: unknown): bigint | undefined => {
  if (v === undefined) return undefined;
  if (typeof v !== "string" || !/^\d+$/.test(v)) throw new Error("amounts must be unsigned decimal strings");
  return BigInt(v);
};

export function policyFromJson(value: unknown): Policy {
  const o = object(value);
  keys(o, ["version", "expiresIn", "label", "allowedPrograms", "limits", "restrictAssets", "frequency"]);
  if (o.version !== 2 || (o.restrictAssets !== undefined && typeof o.restrictAssets !== "boolean") || (o.label !== undefined && typeof o.label !== "string")) throw new Error("invalid V2 policy");
  if (o.allowedPrograms !== undefined && !Array.isArray(o.allowedPrograms)) throw new Error("invalid allowedPrograms");
  if (o.limits !== undefined && !Array.isArray(o.limits)) throw new Error("invalid limits");
  if (o.frequency !== undefined) keys(object(o.frequency), ["maxExecutions", "periodSecs"]);
  const p: Policy = { ...o, allowedPrograms: o.allowedPrograms?.map((k: string) => new PublicKey(k)), limits: o.limits?.map((v: unknown) => {
    const l = object(v);
    keys(l, ["mint", "amount", "periodSecs", "maxPerExecute"]);
    return { mint: new PublicKey(l.mint), amount: amount(l.amount), periodSecs: l.periodSecs, maxPerExecute: amount(l.maxPerExecute) };
  }) } as Policy;
  encodePolicy(p);
  return p;
}
