## Llogaritë e `solanaauth`: madhësia dhe rent-i

Lexuar nga llogaritë që krijon skenari M2 në LiteSVM (CI), me rent-in e rrjetit (minimumi pa rent).

| Llogaria | Bytes | Rent (lamports) | Rent (SOL) | Shënim |
|---|---:|---:|---:|---|
| `Config` | 96 | 1,559,040 | 0.001559 | një për program |
| `Jwk` | 192 | 2,227,200 | 0.002227 | një për (iss, kid); paguan oracle/admini |
| `Wallet` | 416 | 3,786,240 | 0.003786 | një për përdorues; rent-i paguhet një herë |
| `Vault` | 0 | 890,880 | 0.000891 | pa të dhëna (D4); mban SOL-in e përdoruesit |
| `Session` | 640 | 5,345,280 | 0.005345 | një për pajisje/agjent; rent-i kthehet me `close_session` |
