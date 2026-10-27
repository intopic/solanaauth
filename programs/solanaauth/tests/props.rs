//! Teste vetish (property) për parsimin e input-eve dhe kontrollin e politikave: asnjë input
//! s'shkakton panic, dhe limitet e shpenzimit s'tejkalohen kurrë në asnjë dritare.

use proptest::prelude::*;
use solana_address::Address;
use solanaauth::{
    iss::{decode_claim, MAX_ISS_B64},
    passkey::{b64url32, check_client_data},
    policy::{charge, Policy},
    state::Session,
    util::{Account, Reader},
    zk::ZkBlock,
};

fn new_session(buf: &mut [u8]) -> &mut Session {
    Session::init_bytes(buf).unwrap()
}

fn encode_policy(expires: u32, programs: &[[u8; 32]], limits: &[([u8; 32], u64, u32)]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&expires.to_le_bytes());
    v.extend_from_slice(&0u64.to_le_bytes());
    v.extend_from_slice(&[7u8; 32]);
    v.push(programs.len() as u8);
    for p in programs {
        v.extend_from_slice(p);
    }
    v.push(limits.len() as u8);
    for (m, a, p) in limits {
        v.extend_from_slice(m);
        v.extend_from_slice(&a.to_le_bytes());
        v.extend_from_slice(&p.to_le_bytes());
    }
    v
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn policy_read_never_panics(data in proptest::collection::vec(any::<u8>(), 0..700)) {
        let mut r = Reader::new(&data);
        if let Ok(p) = Policy::read(&mut r) {
            let mut buf = vec![0u8; Session::LEN];
            let s = new_session(&mut buf);
            let _ = p.apply(s, 0, &Address::new_from_array([9; 32]));
            prop_assert!(s.n_programs as usize <= 8 && s.n_limits as usize <= 4);
        }
    }

    #[test]
    fn zk_block_read_never_panics(data in proptest::collection::vec(any::<u8>(), 0..1200)) {
        let mut r = Reader::new(&data);
        let _ = ZkBlock::read(&mut r);
    }

    #[test]
    fn iss_decode_never_panics(s in proptest::collection::vec(any::<u8>(), 0..200), idx in 0u8..6) {
        let mut out = [0u8; MAX_ISS_B64];
        let _ = decode_claim(&s, idx, &mut out);
    }

    #[test]
    fn client_data_never_panics(cd in proptest::collection::vec(any::<u8>(), 0..400), ch in any::<[u8; 32]>()) {
        let _ = check_client_data(&cd, &ch);
    }

    /// Pranohet vetëm challenge-i i saktë, një herë, me `type` webauthn.get.
    #[test]
    fn client_data_challenge(ch in any::<[u8; 32]>(), other in any::<[u8; 32]>(), origin in "[a-z]{1,20}") {
        let c = String::from_utf8(b64url32(&ch).to_vec()).unwrap();
        let o = String::from_utf8(b64url32(&other).to_vec()).unwrap();
        let ok = format!(r#"{{"type":"webauthn.get","challenge":"{c}","origin":"https://{origin}"}}"#);
        prop_assert!(check_client_data(ok.as_bytes(), &ch).is_ok());
        if ch != other {
            let wrong = format!(r#"{{"type":"webauthn.get","challenge":"{o}"}}"#);
            prop_assert!(check_client_data(wrong.as_bytes(), &ch).is_err());
        }
        let twice = format!(r#"{{"type":"webauthn.get","challenge":"{c}","challenge":"{c}"}}"#);
        prop_assert!(check_client_data(twice.as_bytes(), &ch).is_err());
        let create = format!(r#"{{"type":"webauthn.create","challenge":"{c}"}}"#);
        prop_assert!(check_client_data(create.as_bytes(), &ch).is_err());
    }

    /// Për çdo varg shpenzimesh: shuma e pranuar në çdo dritare ≤ limiti; asetet pa limit refuzohen.
    #[test]
    fn spend_limit_holds(
        limit in 1u64..1_000_000,
        period in 1u32..1000,
        ops in proptest::collection::vec((0u64..400_000, 0i64..300, any::<bool>()), 1..60),
    ) {
        let mint = [5u8; 32];
        let mut buf = vec![0u8; Session::LEN];
        let s = new_session(&mut buf);
        let enc = encode_policy(3600, &[[1; 32]], &[(mint, limit, period)]);
        Policy::read(&mut Reader::new(&enc)).unwrap().apply(s, 0, &Address::new_from_array([9; 32])).unwrap();

        let mut now = 0i64;
        let mut window_start = 0i64;
        let mut accepted_in_window = 0u64;
        for (amount, dt, other_mint) in ops {
            now += dt;
            if other_mint {
                prop_assert!(amount == 0 || charge(s, &[6u8; 32], amount, now).is_err());
                continue;
            }
            if now >= window_start + period as i64 {
                window_start = now;
                accepted_in_window = 0;
            }
            match charge(s, &mint, amount, now) {
                Ok(()) => {
                    if amount > 0 {
                        accepted_in_window += amount;
                    }
                }
                Err(_) => prop_assert!(accepted_in_window + amount > limit),
            }
            prop_assert!(accepted_in_window <= limit);
            prop_assert!(s.limits[0].spent.get() <= limit);
        }
    }

    /// Politika e koduar nga SDK-ja lexohet dhe zbatohet pa humbje; dublikatat dhe period 0 refuzohen.
    #[test]
    fn policy_roundtrip(
        expires in 1u32..u32::MAX,
        programs in proptest::collection::btree_set(any::<[u8; 32]>(), 0..8),
        limits in proptest::collection::btree_map(any::<[u8; 32]>(), (any::<u64>(), 1u32..u32::MAX), 0..4),
        now in 0i64..1_000_000_000,
    ) {
        let programs: Vec<[u8; 32]> = programs.into_iter().filter(|p| p != &[9; 32] && p[0] != 2).collect();
        let limits: Vec<([u8; 32], u64, u32)> = limits.into_iter().map(|(m, (a, p))| (m, a, p)).collect();
        let enc = encode_policy(expires, &programs, &limits);
        let mut r = Reader::new(&enc);
        let p = Policy::read(&mut r).unwrap();
        prop_assert!(r.data.is_empty());
        let mut buf = vec![0u8; Session::LEN];
        let s = new_session(&mut buf);
        let self_id = Address::new_from_array([9; 32]);
        match p.apply(s, now, &self_id) {
            Ok(()) => {
                prop_assert_eq!(s.programs(), &programs[..]);
                prop_assert_eq!(s.n_limits as usize, limits.len());
                for (i, (m, a, per)) in limits.iter().enumerate() {
                    prop_assert_eq!(&s.limits[i].mint, m);
                    prop_assert_eq!(s.limits[i].amount.get(), *a);
                    prop_assert_eq!(s.limits[i].period_secs.get(), *per);
                    prop_assert_eq!(s.limits[i].window_start.get(), now);
                }
            }
            // E vetmja arsye e lejuar: një program i ndaluar (loader/native).
            Err(_) => prop_assert!(programs.iter().any(|p| solanaauth::policy::is_forbidden(&Address::new_from_array(*p), &self_id))),
        }
    }
}
