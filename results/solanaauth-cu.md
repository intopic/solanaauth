## Matjet e CU — programi `solanaauth` (M2)

Të gjitha numrat vijnë nga LiteSVM në CI, me programin e ndërtuar me `cargo build-sbf`.

| Instruksioni | CU | Tx (bytes) | Shënim |
|---|---:|---:|---|
| init_config | 7,729 | 495 | një herë, nga upgrade authority |
| propose_jwk | 25,468 | 751 | oracle; Poseidon i modulus-it 2048-bit on-chain + krijimi i llogarisë |
| apply_jwk | 218 | 243 | kushdo, pas timelock-ut |
| update_config | 339 | 429 | admin |
| create_wallet | 109,496 | 894 | Google, vk mainnet: verify_full + PDA + krijimi i Wallet |
| open_session | 108,147 | 1124 | verify_full + identiteti + Session (2 programe, 2 limite) |
| execute: transfer SOL | 2,575 | 494 | 1 CPI te System, brenda limitit |
| execute: transfer token | 2,917 | 526 | 1 CPI te SPL Token, matja para/pas |
| execute: SOL + token | 4,602 | 612 | 2 CPI në një instruksion |
| close_session | 530 | 309 | pas skadimit; rent-i kthehet te vault-i |
| create_wallet + open_session | 111,883 | 1000 | hyrja e parë në një instruksion (vk test, allow_test_vk = 1) |
| revoke_session (zk) | 103,939 | 844 | me provë të re zkLogin |
| close_session (pas revokimit) | 527 | 309 |  |
| open_session (vk test) | 107,073 | 999 |  |
| revoke_session (self) | 197 | 374 | nga çelësi i sesionit |
| revoke_jwk | 323 | 373 | admin, menjëherë |

### Testet negative: 35/35 të refuzuara me kodin e pritur

| Rasti | Kodi |
|---|---:|
| init_config nga dikush që s'është upgrade authority | `Custom(4)` |
| propose_jwk nga dikush që s'është admin/oracle | `Custom(4)` |
| create_wallet me JWK ende në timelock | `Custom(11)` |
| apply_jwk para timelock-ut | `Custom(20)` |
| apply_jwk pa ndryshim në pritje | `Custom(21)` |
| create_wallet: 1 byte i ndryshuar në provë | `Custom(10)` |
| create_wallet: session_key tjetër nga eph_pubkey i provës | `Custom(10)` |
| create_wallet: session_key nuk nënshkruan | `Custom(3)` |
| create_wallet: JWK i lëshuesit tjetër (iss mismatch) | `Custom(12)` |
| create_wallet: verifying key test kur allow_test_vk = 0 | `Custom(16)` |
| create_wallet: adresë portofoli që s'del nga identiteti | `Custom(2)` |
| create_wallet: max_epoch > now + max_session_secs | `Custom(15)` |
| update_config nga oracle (jo admin) | `Custom(4)` |
| create_wallet: prova ka skaduar (now >= max_epoch) | `Custom(14)` |
| create_wallet: portofoli ekziston | `Custom(5)` |
| open_session: politika lejon vetë programin solanaauth | `Custom(40)` |
| open_session: verifying key test kur allow_test_vk = 0 | `Custom(16)` |
| open_session: sesioni ekziston | `Custom(5)` |
| execute: SOL mbi limitin e dritares | `Custom(33)` |
| execute: token mbi limitin (300 + 201 > 500) | `Custom(33)` |
| execute: token pa limit (deny by default) | `Custom(34)` |
| execute: Approve (delegate) mbi token account të vault-it | `Custom(36)` |
| execute: Assign i vault-it te një program tjetër | `Custom(35)` |
| execute: program jashtë allowlist-it | `Custom(32)` |
| execute: CPI te vetë programi | `Custom(37)` |
| execute: fee payer-i si nënshkrues i instruksionit të brendshëm | `Custom(3)` |
| execute: nënshkrues që s'është session_key | `Custom(2)` |
| execute: portofoli si llogari e instruksionit të brendshëm | `Custom(2)` |
| close_session: sesioni ende aktiv | `Custom(39)` |
| execute: sesioni ka skaduar | `Custom(30)` |
| revoke_session (zk): identitet që s'është i portofolit | `Custom(18)` |
| execute: sesioni i revokuar | `Custom(31)` |
| revoke_session (self): nënshkrues tjetër | `Custom(2)` |
| revoke_jwk nga oracle (jo admin) | `Custom(4)` |
| open_session me JWK të revokuar | `Custom(11)` |

<sub>solanaauth.so: 89,768 bytes</sub>
