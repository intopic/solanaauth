//! Ndihmës për matjet e CU: kthen fixtures e `reference` në instruksione për
//! programin `zklogin-verifier`, dhe gjeneron raportin `results/cu-report.{json,md}`.

use std::fmt::Write as _;

use num_bigint::BigUint;
use reference::Fixture;
use zklogin_verifier::inputs::{self, Circuit, Fe, Modulus, ZkLoginPublicInputs};
use zklogin_verifier::vk::VkId;
use zklogin_verifier::{OP_COMPUTE_INPUTS_HASH, OP_VERIFY_FULL, OP_VERIFY_PROOF, TRACE};

pub mod svm;

pub mod negative {
    //! Detyra 7: raste negative, 1 byte i ndryshuar në provë ose në input.
    use super::{Case, ModulusMode};
    use zklogin_verifier::inputs::Modulus;
    use zklogin_verifier::vk::VkId;

    pub struct NegCase {
        pub label: String,
        pub data: Vec<u8>,
    }

    fn flip(bytes: &mut [u8], i: usize) {
        bytes[i] ^= 0x01;
    }

    /// Fixtures mbi të cilat ndërtohen rastet negative.
    pub const FIXTURES: [&str; 2] = ["google-mainnet-v1", "dev-v1-pinned"];

    pub fn cases() -> Vec<(String, NegCase)> {
        let mut out = Vec::new();
        for name in FIXTURES {
            let c = Case::load(name);
            let hash = c.all_inputs_hash();
            let mut push = |label: &str, data: Vec<u8>| {
                out.push((
                    name.to_string(),
                    NegCase {
                        label: label.to_string(),
                        data,
                    },
                ))
            };

            // verify_proof
            for (label, idx) in [
                ("verify_proof: 1 byte në A", 63),
                ("verify_proof: 1 byte në B", 191),
                ("verify_proof: 1 byte në C", 255),
            ] {
                let mut proof = c.proof;
                flip(&mut proof, idx);
                push(label, c.ix_verify_proof(&proof, &hash, false));
            }
            let mut bad_input = hash;
            flip(&mut bad_input, 31);
            push(
                "verify_proof: 1 byte në input-in publik",
                c.ix_verify_proof(&c.proof, &bad_input, false),
            );
            let mut wrong_vk = c.ix_verify_proof(&c.proof, &hash, false);
            wrong_vk[1] = if c.vk == VkId::Mainnet {
                VkId::DevV1 as u8
            } else {
                VkId::Mainnet as u8
            };
            push("verify_proof: verifying key tjetër (main ↔ test)", wrong_vk);

            // verify_full
            let p = c.public_inputs(ModulusMode::Full);
            let mut proof = c.proof;
            flip(&mut proof, 63);
            push(
                "verify_full: 1 byte në provë (A)",
                c.ix_verify_full(&p, &proof, false),
            );
            let mut proof = c.proof;
            flip(&mut proof, 255);
            push(
                "verify_full: 1 byte në provë (C)",
                c.ix_verify_full(&p, &proof, false),
            );

            let mut pk = c.eph_pubkey;
            flip(&mut pk, 31);
            push(
                "verify_full: 1 byte në çelësin ephemeral",
                c.ix_verify_full(
                    &super::ZkLoginPublicInputs {
                        eph_pubkey: &pk,
                        ..p
                    },
                    &c.proof,
                    false,
                ),
            );
            push(
                "verify_full: max_epoch + 1",
                c.ix_verify_full(
                    &super::ZkLoginPublicInputs {
                        max_epoch: p.max_epoch + 1,
                        ..p
                    },
                    &c.proof,
                    false,
                ),
            );
            let mut seed = c.address_seed;
            flip(&mut seed, 31);
            push(
                "verify_full: 1 byte në address_seed",
                c.ix_verify_full(
                    &super::ZkLoginPublicInputs {
                        address_seed: &seed,
                        ..p
                    },
                    &c.proof,
                    false,
                ),
            );
            let mut iss = c.iss.clone();
            let last = iss.len() - 1;
            flip(&mut iss, last);
            push(
                "verify_full: 1 byte në iss",
                c.ix_verify_full(
                    &super::ZkLoginPublicInputs { iss: &iss, ..p },
                    &c.proof,
                    false,
                ),
            );
            push(
                "verify_full: index_mod_4 tjetër",
                c.ix_verify_full(
                    &super::ZkLoginPublicInputs {
                        index_mod_4: (p.index_mod_4 + 1) % 4,
                        ..p
                    },
                    &c.proof,
                    false,
                ),
            );
            let mut header = c.header.clone();
            flip(&mut header, 0);
            push(
                "verify_full: 1 byte në header",
                c.ix_verify_full(
                    &super::ZkLoginPublicInputs {
                        header_base64: &header,
                        ..p
                    },
                    &c.proof,
                    false,
                ),
            );
            let mut modulus = c.modulus.clone();
            flip(&mut modulus, 100);
            push(
                "verify_full: 1 byte në modulus-in RSA",
                c.ix_verify_full(
                    &super::ZkLoginPublicInputs {
                        modulus: Modulus::Full(&modulus),
                        ..p
                    },
                    &c.proof,
                    false,
                ),
            );
        }
        out
    }
}

/// Numër decimal -> 32 bytes big endian.
pub fn dec_to_be32(s: &str) -> Fe {
    let n: BigUint = s
        .parse()
        .unwrap_or_else(|_| panic!("numër decimal i pavlefshëm: {s}"));
    let bytes = n.to_bytes_be();
    assert!(bytes.len() <= 32, "numri s'futet në 32 bytes: {s}");
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

pub fn be32_to_dec(fe: &Fe) -> String {
    BigUint::from_bytes_be(fe).to_string()
}

/// Konverton `proof_points` (formati circom/snarkjs, decimal, koordinata projektive me z = 1)
/// në `A || B || C` big endian për groth16-solana. Kujdes G2: snarkjs jep `[x.c0, x.c1]`,
/// syscall-et alt_bn128 presin `x.c1 || x.c0` (EIP-197).
pub fn proof_bytes(fx: &Fixture) -> [u8; 256] {
    let pp = &fx.inputs["proof_points"];
    let s = |v: &serde_json::Value| v.as_str().unwrap().to_string();
    let a = pp["a"].as_array().unwrap();
    let b = pp["b"].as_array().unwrap();
    let c = pp["c"].as_array().unwrap();
    assert_eq!(s(&a[2]), "1");
    assert_eq!(s(&c[2]), "1");
    assert_eq!((s(&b[2][0]), s(&b[2][1])), ("1".into(), "0".into()));

    let mut out = [0u8; 256];
    out[0..32].copy_from_slice(&dec_to_be32(&s(&a[0])));
    out[32..64].copy_from_slice(&dec_to_be32(&s(&a[1])));
    out[64..96].copy_from_slice(&dec_to_be32(&s(&b[0][1])));
    out[96..128].copy_from_slice(&dec_to_be32(&s(&b[0][0])));
    out[128..160].copy_from_slice(&dec_to_be32(&s(&b[1][1])));
    out[160..192].copy_from_slice(&dec_to_be32(&s(&b[1][0])));
    out[192..224].copy_from_slice(&dec_to_be32(&s(&c[0])));
    out[224..256].copy_from_slice(&dec_to_be32(&s(&c[1])));
    out
}

pub fn vk_id(fx: &Fixture) -> VkId {
    match fx.vk.as_str() {
        "zkLogin-main.vkey.json" => VkId::Mainnet,
        "zkLogin-test.vkey.json" => VkId::DevV1,
        "zkLogin-dev-v2.vkey.json" => VkId::DevV2,
        other => panic!("vk i panjohur: {other}"),
    }
}

/// Si të dërgohet modulus-i RSA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModulusMode {
    /// Modulus-i i plotë në instruksion, hash-i llogaritet on-chain.
    Full,
    /// Vetëm hash-i i modulus-it (32 bytes) + numri i bit-eve, si nga një JWK registry.
    Precomputed,
}

/// Të gjitha të dhënat e një fixture-i, të gatshme për programin.
pub struct Case {
    pub fx: Fixture,
    pub vk: VkId,
    pub proof: [u8; 256],
    pub eph_pubkey: [u8; 32],
    pub address_seed: Fe,
    /// V1: iss base64; V2: claim-i i dekoduar.
    pub iss: Vec<u8>,
    pub index_mod_4: u8,
    pub header: Vec<u8>,
    pub modulus: Vec<u8>,
    /// Hash-i i modulus-it, i llogaritur off-chain (me Poseidon me copa si në Sui).
    pub modulus_hash: Fe,
}

impl Case {
    pub fn load(name: &str) -> Self {
        let fx = Fixture::load(name);
        let zk = fx.zklogin_inputs();
        let vk = vk_id(&fx);
        let iss = match vk.circuit() {
            Circuit::V1 => zk.iss_base64_details().value.clone().into_bytes(),
            Circuit::V2 => zk
                .iss_base64_details()
                .decoded_extended_claim()
                .expect("iss i pavlefshëm")
                .into_bytes(),
        };
        let modulus = fx.modulus();
        let modulus_hash = offchain_modulus_hash(&modulus, vk.circuit().max_modulus_len());
        Case {
            vk,
            proof: proof_bytes(&fx),
            eph_pubkey: reference::ephemeral_public_key(&fx),
            address_seed: dec_to_be32(fx.inputs["address_seed"].as_str().unwrap()),
            iss,
            index_mod_4: zk.iss_base64_details().index_mod_4,
            header: zk.header_base64().as_bytes().to_vec(),
            modulus,
            modulus_hash,
            fx,
        }
    }

    pub fn public_inputs(&self, mode: ModulusMode) -> ZkLoginPublicInputs<'_> {
        ZkLoginPublicInputs {
            circuit: self.vk.circuit(),
            eph_pubkey: &self.eph_pubkey,
            max_epoch: self.fx.max_epoch,
            address_seed: &self.address_seed,
            iss: &self.iss,
            index_mod_4: self.index_mod_4,
            header_base64: &self.header,
            modulus: match mode {
                ModulusMode::Full => Modulus::Full(&self.modulus),
                ModulusMode::Precomputed => Modulus::Precomputed {
                    hash: &self.modulus_hash,
                    num_bits: inputs::modulus_num_bits(&self.modulus) as u16,
                },
            },
        }
    }

    /// `all_inputs_hash` i llogaritur me kodin e programit (në host), me modulus të para-llogaritur
    /// (funksionon për v1 dhe v2).
    pub fn all_inputs_hash(&self) -> Fe {
        inputs::all_inputs_hash(&self.public_inputs(ModulusMode::Precomputed), |_| {}).unwrap()
    }

    pub fn ix_verify_proof(&self, proof: &[u8; 256], public_input: &Fe, trace: bool) -> Vec<u8> {
        let mut d = vec![
            OP_VERIFY_PROOF | if trace { TRACE } else { 0 },
            self.vk as u8,
        ];
        d.extend_from_slice(proof);
        d.extend_from_slice(public_input);
        d
    }

    fn ix_with_inputs(
        &self,
        op: u8,
        p: &ZkLoginPublicInputs<'_>,
        proof: &[u8; 256],
        trace: bool,
    ) -> Vec<u8> {
        let mut d = vec![op | if trace { TRACE } else { 0 }, self.vk as u8];
        d.extend_from_slice(proof);
        d.extend_from_slice(p.eph_pubkey);
        d.extend_from_slice(&p.max_epoch.to_le_bytes());
        d.extend_from_slice(p.address_seed);
        d.push(p.index_mod_4);
        d.push(u8::try_from(p.iss.len()).unwrap());
        d.extend_from_slice(p.iss);
        d.extend_from_slice(&u16::try_from(p.header_base64.len()).unwrap().to_le_bytes());
        d.extend_from_slice(p.header_base64);
        match p.modulus {
            Modulus::Full(m) => {
                d.push(0);
                d.extend_from_slice(&u16::try_from(m.len()).unwrap().to_le_bytes());
                d.extend_from_slice(m);
            }
            Modulus::Precomputed { hash, num_bits } => {
                d.push(1);
                d.extend_from_slice(hash);
                d.extend_from_slice(&num_bits.to_le_bytes());
            }
        }
        d
    }

    pub fn ix_verify_full(
        &self,
        p: &ZkLoginPublicInputs<'_>,
        proof: &[u8; 256],
        trace: bool,
    ) -> Vec<u8> {
        self.ix_with_inputs(OP_VERIFY_FULL, p, proof, trace)
    }

    pub fn ix_compute_inputs_hash(&self, p: &ZkLoginPublicInputs<'_>) -> Vec<u8> {
        self.ix_with_inputs(OP_COMPUTE_INPUTS_HASH, p, &self.proof, false)
    }
}

/// Hash-i i modulus-it si në sui-crypto `modulus_to_field`: modulus-i mbushet majtas deri
/// në `max_len` bytes, ndahet në copa 31-byte nga e djathta, dhe Poseidon-i i Sui-t
/// (deri në 16 input-e direkt, më shumë me copa nga 16) aplikohet mbi to.
pub fn offchain_modulus_hash(modulus: &[u8], max_len: usize) -> Fe {
    use ark_ff_04::{BigInteger, PrimeField};
    type Fr = ark_bn254_04::Fr;

    let mut padded = vec![0u8; max_len - modulus.len()];
    padded.extend_from_slice(modulus);
    let mut chunks: Vec<Fr> = padded
        .rchunks(31)
        .map(Fr::from_be_bytes_mod_order)
        .collect();
    chunks.reverse();

    fn sui_poseidon(p: &poseidon_ark::Poseidon, inp: &[Fr]) -> Fr {
        if inp.len() > 16 {
            let hashes: Vec<Fr> = inp.chunks(16).map(|c| sui_poseidon(p, c)).collect();
            return sui_poseidon(p, &hashes);
        }
        p.hash(inp.to_vec()).unwrap()
    }
    let h = sui_poseidon(&poseidon_ark::Poseidon::new(), &chunks);
    let bytes = h.into_bigint().to_bytes_be();
    bytes.try_into().unwrap()
}

/// Raporti i matjeve.
#[derive(Default)]
pub struct Report {
    pub sections: Vec<Section>,
    pub negatives: Vec<NegativeCase>,
    pub notes: Vec<String>,
    /// CU totale e `verify_full` për fixture-in kryesor (Google, mainnet).
    pub decisive_cu: Option<u64>,
    pub decisive_label: String,
    pub meta: Vec<(String, String)>,
}

pub struct Section {
    pub fixture: String,
    pub description: String,
    pub rows: Vec<Row>,
}

pub struct Row {
    pub name: String,
    pub cu: Option<u64>,
    /// Madhësia e transaksionit (bytes), kur ka kuptim.
    pub tx_bytes: Option<usize>,
    pub note: String,
}

pub struct NegativeCase {
    pub fixture: String,
    pub case: String,
    pub rejected: bool,
    pub detail: String,
}

/// Kufijtë GO / NO-GO për `verify_full` (shih docs/HAPI-1-BRIEF.md).
pub fn verdict(total_cu: Option<u64>) -> &'static str {
    match total_cu {
        None => "PA MATJE",
        Some(c) if c <= 400_000 => "GO",
        Some(c) if c <= 1_000_000 => "GO me kujdes",
        Some(c) if c <= 1_400_000 => "Rishikim",
        Some(_) => "NO-GO",
    }
}

fn fmt_num(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

fn json_str(s: &str) -> String {
    serde_json::Value::String(s.to_string()).to_string()
}

impl Report {
    pub fn render_markdown(&self) -> String {
        let mut s = String::from("## Matjet e CU — zklogin-verifier\n\n");
        let _ = writeln!(
            s,
            "**Vendimi:** {} — `verify_full` ({}) = **{} CU** nga limiti 1,400,000 CU i transaksionit.\n",
            verdict(self.decisive_cu),
            self.decisive_label,
            self.decisive_cu.map(fmt_num).unwrap_or_else(|| "—".into())
        );
        for sec in &self.sections {
            let _ = writeln!(s, "### `{}`\n\n{}\n", sec.fixture, sec.description);
            s.push_str("| Matja | CU | Tx (bytes) | Shënim |\n|---|---:|---:|---|\n");
            for r in &sec.rows {
                let cu = r.cu.map(fmt_num).unwrap_or_else(|| "—".into());
                let tx = r.tx_bytes.map(|b| b.to_string()).unwrap_or_default();
                let _ = writeln!(s, "| {} | {} | {} | {} |", r.name, cu, tx, r.note);
            }
            s.push('\n');
        }
        if !self.negatives.is_empty() {
            let ok = self.negatives.iter().filter(|n| n.rejected).count();
            let _ = writeln!(
                s,
                "### Testet negative: {ok}/{} të refuzuara\n",
                self.negatives.len()
            );
            s.push_str("| Fixture | Ndryshimi | Rezultati |\n|---|---|---|\n");
            for n in &self.negatives {
                let res = if n.rejected {
                    "refuzohet ✅"
                } else {
                    "PRANOHET ❌"
                };
                let _ = writeln!(
                    s,
                    "| `{}` | {} | {} ({}) |",
                    n.fixture, n.case, res, n.detail
                );
            }
            s.push('\n');
        }
        if !self.notes.is_empty() {
            s.push_str("### Shënime\n\n");
            for n in &self.notes {
                let _ = writeln!(s, "- {n}");
            }
            s.push('\n');
        }
        if !self.meta.is_empty() {
            s.push_str("<sub>");
            let parts: Vec<String> = self
                .meta
                .iter()
                .map(|(k, v)| format!("{k}: `{v}`"))
                .collect();
            s.push_str(&parts.join(" · "));
            s.push_str("</sub>\n");
        }
        s
    }

    pub fn render_json(&self) -> String {
        let mut s = String::from("{\n");
        let _ = writeln!(s, "  \"verdict\": {},", json_str(verdict(self.decisive_cu)));
        let _ = writeln!(
            s,
            "  \"decisive\": {{ \"label\": {}, \"verify_full_cu\": {} }},",
            json_str(&self.decisive_label),
            self.decisive_cu
                .map(|c| c.to_string())
                .unwrap_or_else(|| "null".into())
        );
        s.push_str("  \"fixtures\": [\n");
        let secs: Vec<String> = self
            .sections
            .iter()
            .map(|sec| {
                let rows: Vec<String> = sec
                    .rows
                    .iter()
                    .map(|r| {
                        format!(
                            "        {{ \"name\": {}, \"cu\": {}, \"tx_bytes\": {}, \"note\": {} }}",
                            json_str(&r.name),
                            r.cu.map(|c| c.to_string()).unwrap_or_else(|| "null".into()),
                            r.tx_bytes.map(|c| c.to_string()).unwrap_or_else(|| "null".into()),
                            json_str(&r.note)
                        )
                    })
                    .collect();
                format!(
                    "    {{\n      \"fixture\": {},\n      \"measurements\": [\n{}\n      ]\n    }}",
                    json_str(&sec.fixture),
                    rows.join(",\n")
                )
            })
            .collect();
        s.push_str(&secs.join(",\n"));
        s.push_str("\n  ],\n  \"negative_tests\": [\n");
        let negs: Vec<String> = self
            .negatives
            .iter()
            .map(|n| {
                format!(
                    "    {{ \"fixture\": {}, \"case\": {}, \"rejected\": {}, \"detail\": {} }}",
                    json_str(&n.fixture),
                    json_str(&n.case),
                    n.rejected,
                    json_str(&n.detail)
                )
            })
            .collect();
        s.push_str(&negs.join(",\n"));
        s.push_str("\n  ],\n  \"meta\": {");
        let meta: Vec<String> = self
            .meta
            .iter()
            .map(|(k, v)| format!(" {}: {}", json_str(k), json_str(v)))
            .collect();
        s.push_str(&meta.join(","));
        s.push_str(" }\n}\n");
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn thresholds() {
        assert_eq!(verdict(Some(350_000)), "GO");
        assert_eq!(verdict(Some(400_000)), "GO");
        assert_eq!(verdict(Some(900_000)), "GO me kujdes");
        assert_eq!(verdict(Some(1_200_000)), "Rishikim");
        assert_eq!(verdict(Some(1_500_000)), "NO-GO");
        assert_eq!(verdict(None), "PA MATJE");
    }

    #[test]
    fn number_format() {
        assert_eq!(fmt_num(1_400_000), "1,400,000");
        assert_eq!(fmt_num(999), "999");
    }
}
