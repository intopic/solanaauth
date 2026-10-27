## Matjet e CU — `solanaauth` M3 (passkey, pragu, rikuperimi)

Nga LiteSVM në CI. CU e instruksionit `solanaauth` (pa precompile-in secp256r1, që nuk konsumon CU të programit).

| Instruksioni | CU | Tx (bytes) | Shënim |
|---|---:|---:|---|
| add_passkey (zk) | 105,224 | 894 | passkey-i i parë, me provë zkLogin |
| add_passkey (passkey) | 3,105 | 667 | secp256r1 + WebAuthn + nonce |
| set_threshold | 2,898 | 640 | 1 SOL në 24 orë pa passkey |
| execute nën prag | 2,641 | 494 | transfer SOL, pragu ditor përditësohet |
| execute me passkey (mbi prag) | 5,456 | 883 | sesion + passkey |
| remove_passkey | 2,820 | 633 |  |
| begin_recovery (zk → passkey) | 105,485 | 894 | humbi passkey-n; timelock 48 orë |
| cancel_recovery (passkey) | 2,781 | 633 | pronari anulon rikuperimin e filluar me Google |
| begin_recovery (passkey → zk) | 107,333 | 1200 | humbi Google/salt: provë e identitetit të ri + passkey |
| cancel_recovery (zk) | 104,782 | 860 | identiteti ekzistues anulon |
| revoke_session (passkey) | 2,889 | 666 |  |
| finish_recovery | 232 | 276 | kushdo, pas timelock-ut |

### Testet negative: 17/17 të refuzuara me kodin e pritur

| Rasti | Kodi |
|---|---:|
| add_passkey (zk) kur portofoli ka passkey | `Custom(41)` |
| add_passkey: passkey që s'është i portofolit | `Custom(41)` |
| add_passkey: slot i zënë | `Custom(46)` |
| passkey: replay i të njëjtit nënshkrim (nonce) | `Custom(42)` |
| passkey: nënshkrim P-256 i pavlefshëm | precompile secp256r1 |
| passkey: clientDataJSON me challenge tjetër | `Custom(42)` |
| passkey: pa instruksionin e precompile-it | `Custom(42)` |
| passkey: të dhëna të ndryshuara pas nënshkrimit | `Custom(42)` |
| execute: SOL mbi pragun ditor pa passkey | `Custom(45)` |
| execute me passkey që s'është i portofolit | `Custom(41)` |
| remove_passkey me passkey-n e hequr | `Custom(41)` |
| finish_recovery pa rikuperim | `Custom(44)` |
| begin_recovery kur ka një në pritje | `Custom(43)` |
| finish_recovery para timelock-ut | `Custom(20)` |
| cancel_recovery me identitet që s'është ende i portofolit | `Custom(18)` |
| execute pas revokimit me passkey | `Custom(31)` |
| finish_recovery 1 sekondë para eta | `Custom(20)` |

<sub>solanaauth.so: 89,808 bytes</sub>
