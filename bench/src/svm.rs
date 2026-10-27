//! Ekzekutimi i programit `.so` në LiteSVM (SVM lokal me feature set-in e Agave 4.x).

use std::path::{Path, PathBuf};

use litesvm::LiteSVM;
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;

/// Limiti maksimal i CU për një transaksion në Solana.
pub const MAX_TX_CU: u32 = 1_400_000;
/// Limiti i madhësisë së një transaksioni (bytes, paketa IPv6 minimale - header-at).
pub const MAX_TX_BYTES: usize = 1232;

/// Rruga e paracaktuar e programit të ndërtuar me `cargo build-sbf`.
pub fn default_program_path() -> PathBuf {
    if let Ok(p) = std::env::var("ZKLOGIN_VERIFIER_SO") {
        return PathBuf::from(p);
    }
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../programs/zklogin-verifier/target/deploy/zklogin_verifier.so")
}

pub struct Outcome {
    pub ok: bool,
    /// CU e konsumuar nga instruksioni i programit (nga log-u "consumed N of M").
    pub cu: u64,
    /// CU totale e transaksionit sipas LiteSVM.
    pub tx_cu: u64,
    pub logs: Vec<String>,
    pub err: Option<String>,
    pub tx_bytes: usize,
}

impl Outcome {
    /// Vlerat "Program consumption: N units remaining" nga `sol_log_compute_units`.
    pub fn remaining_marks(&self) -> Vec<u64> {
        self.logs
            .iter()
            .filter_map(|l| {
                l.strip_prefix("Program consumption: ")?
                    .strip_suffix(" units remaining")?
                    .parse()
                    .ok()
            })
            .collect()
    }

    /// Të dhënat e `sol_log_data` (base64) nga log-et.
    pub fn data_logs(&self) -> Vec<String> {
        self.logs
            .iter()
            .filter_map(|l| l.strip_prefix("Program data: ").map(str::to_string))
            .collect()
    }
}

pub struct Svm {
    svm: LiteSVM,
    payer: Keypair,
    pub program_id: Address,
}

impl Svm {
    pub fn new(so: &Path) -> Self {
        let mut svm = LiteSVM::new();
        let program_id = Address::new_from_array([7u8; 32]);
        svm.add_program_from_file(program_id, so)
            .unwrap_or_else(|e| panic!("s'ngarkohet {}: {e:?}", so.display()));
        let payer = Keypair::new();
        svm.airdrop(&payer.pubkey(), 10_000_000_000).unwrap();
        Svm {
            svm,
            payer,
            program_id,
        }
    }

    pub fn transaction(&self, data: Vec<u8>) -> Transaction {
        let ixs = [
            ComputeBudgetInstruction::set_compute_unit_limit(MAX_TX_CU),
            Instruction {
                program_id: self.program_id,
                accounts: vec![],
                data,
            },
        ];
        let msg = Message::new(&ixs, Some(&self.payer.pubkey()));
        Transaction::new(&[&self.payer], msg, self.svm.latest_blockhash())
    }

    pub fn tx_size(tx: &Transaction) -> usize {
        // shortvec(numri i nënshkrimeve) + nënshkrimet + mesazhi i serializuar
        1 + 64 * tx.signatures.len() + tx.message.serialize().len()
    }

    pub fn run(&mut self, data: Vec<u8>) -> Outcome {
        self.svm.expire_blockhash();
        let tx = self.transaction(data);
        let tx_bytes = Self::tx_size(&tx);
        let (ok, meta, err) = match self.svm.send_transaction(tx) {
            Ok(meta) => (true, meta, None),
            Err(f) => (false, f.meta, Some(format!("{:?}", f.err))),
        };
        let prefix = format!("Program {} consumed ", self.program_id);
        let cu = meta
            .logs
            .iter()
            .find_map(|l| l.strip_prefix(&prefix)?.split(' ').next()?.parse().ok())
            .unwrap_or(meta.compute_units_consumed);
        Outcome {
            ok,
            cu,
            tx_cu: meta.compute_units_consumed,
            logs: meta.logs,
            err,
            tx_bytes,
        }
    }
}
