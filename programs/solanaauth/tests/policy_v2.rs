use solana_address::Address;
use solanaauth::{
    policy::{charge_execution, record_execution, Policy},
    state::{Session, SessionRules},
    util::{Account, Reader},
};

fn encoded(
    flags: u8,
    limit: Option<(u8, u64, u32, u64)>,
    frequency: Option<(u32, u32)>,
) -> Vec<u8> {
    let mut b = vec![0; 4];
    b.extend_from_slice(&[2, flags]);
    b.extend_from_slice(&3600u32.to_le_bytes());
    b.extend_from_slice(&[0; 32]);
    b.push(0);
    b.push(u8::from(limit.is_some()));
    if let Some((f, a, p, t)) = limit {
        b.extend_from_slice(&[5; 32]);
        b.push(f);
        b.extend(a.to_le_bytes());
        b.extend(p.to_le_bytes());
        b.extend(t.to_le_bytes());
    }
    if let Some((n, p)) = frequency {
        b.extend(n.to_le_bytes());
        b.extend(p.to_le_bytes());
    }
    b
}
fn session(policy: &[u8]) -> Vec<u8> {
    let p = Policy::read(&mut Reader::new(policy)).unwrap();
    let mut data = vec![0; Session::V2_LEN];
    p.apply(
        Session::init_bytes(&mut data).unwrap(),
        100,
        &Address::new_from_array([9; 32]),
    )
    .unwrap();
    p.apply_rules(&mut data, 100).unwrap();
    data
}

#[test]
fn omitted_rules_are_unrestricted_but_explicit_zero_blocks() {
    let mut d = session(&encoded(3, None, None));
    assert!(Session::from_bytes(&d).unwrap().unrestricted_programs());
    charge_execution(&mut d, &[8; 32], u64::MAX, 100).unwrap();
    let mut d = session(&encoded(3, Some((2, 0, 0, 0)), None));
    assert!(charge_execution(&mut d, &[5; 32], 1, 100).is_err());
    charge_execution(&mut d, &[8; 32], 10, 100).unwrap();
    let mut d = session(&encoded(1, Some((0, 0, 0, 0)), None));
    charge_execution(&mut d, &[5; 32], u64::MAX, 100).unwrap();
    assert!(charge_execution(&mut d, &[8; 32], 1, 100).is_err());
}
#[test]
fn per_execute_and_periodic_caps_combine_and_reset_exactly() {
    let mut d = session(&encoded(3, Some((3, 100, 10, 60)), None));
    assert!(charge_execution(&mut d, &[5; 32], 61, 100).is_err());
    charge_execution(&mut d, &[5; 32], 60, 100).unwrap();
    charge_execution(&mut d, &[5; 32], 40, 109).unwrap();
    assert!(charge_execution(&mut d, &[5; 32], 1, 109).is_err());
    charge_execution(&mut d, &[5; 32], 60, 110).unwrap();
    assert_eq!(Session::from_bytes(&d).unwrap().limits[0].spent.get(), 60);
}
#[test]
fn frequency_exact_boundary_and_zero_limit() {
    let mut d = session(&encoded(7, None, Some((2, 10))));
    record_execution(&mut d, 100).unwrap();
    record_execution(&mut d, 109).unwrap();
    assert!(record_execution(&mut d, 109).is_err());
    record_execution(&mut d, 110).unwrap();
    assert_eq!(SessionRules::from_bytes(&d).unwrap().executions.get(), 1);
    let mut d = session(&encoded(7, None, Some((0, 10))));
    assert!(record_execution(&mut d, 100).is_err());
}
#[test]
fn versioned_layout_rejects_truncation_and_unknown_flags() {
    let d = session(&encoded(3, None, None));
    assert!(Session::from_bytes(&d[..640]).is_err());
    let mut bad = d.clone();
    bad[6] = 8;
    assert!(Session::from_bytes(&bad).is_err());
    assert!(Policy::read(&mut Reader::new(&encoded(8, None, None))).is_err());
    assert!(Policy::read(&mut Reader::new(&encoded(7, None, Some((1, 0))))).is_err());
}
