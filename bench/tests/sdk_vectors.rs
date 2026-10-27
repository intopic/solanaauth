//! Vektorët e testit për SDK-në TypeScript (`sdk/core`): të dhënat e instruksioneve dhe
//! adresat që ndërton klienti Rust i testeve. Shkruhen te `fixtures/sdk-vectors.json`; CI
//! kontrollon që skedari është i përditësuar dhe SDK-ja ndërton të njëjtat bytes.

use bench::auth::*;
use bench::Case;
use solana_address::Address;
use solana_instruction::Instruction;
use solana_signer::Signer;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn ix_json(ix: &Instruction) -> serde_json::Value {
    serde_json::json!({
        "program_id": ix.program_id.to_string(),
        "data": hex(&ix.data),
        "accounts": ix.accounts.iter().map(|m| serde_json::json!({
            "pubkey": m.pubkey.to_string(), "is_signer": m.is_signer, "is_writable": m.is_writable,
        })).collect::<Vec<_>>(),
    })
}

#[test]
fn sdk_vectors() {
    let env = Env::offline();
    let c = Case::load("google-mainnet-v1");
    let k = Address::new_from_array(c.eph_pubkey);
    let iss = "https://accounts.google.com";
    let id = identity(iss, &c.address_seed);
    let wallet = env.wallet_of(&id);
    let jwk = env.jwk(iss, &c.fx.jwk.kid);
    let zk = zk_block(&c, &c.proof);
    let policy = Policy {
        expires_in: 3600,
        label: label("demo"),
        programs: vec![SYSTEM, TOKEN],
        limits: vec![(Address::default(), 1_000_000_000, 86_400)],
    };
    let vault = env.vault(&wallet);
    let dest = Address::new_from_array([5u8; 32]);
    let v = serde_json::json!({
        "program_id": env.program_id.to_string(),
        "payer": env.payer.pubkey().to_string(),
        "admin": env.admin.pubkey().to_string(),
        "oracle": env.oracle.pubkey().to_string(),
        "fixture": "google-mainnet-v1",
        "eph_pubkey": k.to_string(),
        "identity": hex(&id),
        "wallet": wallet.to_string(),
        "vault": vault.to_string(),
        "session": env.session(&wallet, &k).to_string(),
        "config": env.config().to_string(),
        "jwk": jwk.to_string(),
        "zk_block": hex(&zk),
        "policy": hex(&policy.encode()),
        "ix": {
            "init_config": ix_json(&env.ix_init_config(&env.admin.pubkey(), &ConfigParams::default())),
            "propose_jwk": ix_json(&env.ix_propose_jwk(&env.oracle.pubkey(), iss, &c.fx.jwk.kid, &c.modulus, 0, i64::MAX)),
            "apply_jwk": ix_json(&env.ix_apply_jwk(&jwk)),
            "create_wallet": ix_json(&env.ix_create_wallet(&zk, &k, &jwk, &wallet, Some(&policy))),
            "open_session": ix_json(&env.ix_open_session(&zk, &k, &jwk, &wallet, &policy)),
            "execute": ix_json(&env.ix_execute(&k, &wallet, &[system_transfer(&vault, &dest, 1234)])),
            "revoke_self": ix_json(&env.ix_revoke_self(&k, &wallet)),
            "close_session": ix_json(&env.ix_close_session(&wallet, &env.session(&wallet, &k))),
        },
    });
    let out = serde_json::to_string_pretty(&v).unwrap() + "\n";
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../fixtures/sdk-vectors.json");
    if std::env::var("CHECK_SDK_VECTORS").is_ok() {
        let cur = std::fs::read_to_string(&path).unwrap_or_default();
        assert_eq!(cur, out, "fixtures/sdk-vectors.json s'është i përditësuar: cargo test -p bench --test sdk_vectors");
    } else {
        std::fs::write(&path, out).unwrap();
    }
}
