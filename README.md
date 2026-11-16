# SymCrypto Lab
### An end-to-end symmetric-cryptography implementation & cryptanalysis project
*Topic area: **IACR Transactions on Symmetric Cryptology (ToSC)** — the IACR journal on block ciphers, stream ciphers, hash/MAC constructions, modes of operation and their cryptanalysis.*

> **Educational use only.** The ciphers here are pure-Python, not constant-time, and not meant to protect real secrets. For production use a vetted library (e.g. `cryptography`, libsodium).

## 1. What the project does

| Module | Content | ToSC topic it maps to |
|---|---|---|
| `symlab/aes.py` | AES-128/192/256 from scratch (S-box generated from GF(2^8) maths) | Block cipher design (SPN) |
| `symlab/chacha20.py` | ChaCha20 (RFC 8439), configurable rounds | Stream ciphers / ARX |
| `symlab/speck.py` | Speck128/128 | Lightweight cryptography / ARX |
| `symlab/modes.py` | CTR, CBC, PKCS#7, ECB (insecure demo) | Modes of operation |
| `symlab/container.py` | Authenticated file format: PBKDF2 → cipher → HMAC-SHA256 (Encrypt-then-MAC) | Authenticated encryption, key derivation |
| `symlab/toy_spn.py` | 16-bit SPN (PRESENT S-box + bit permutation) | Cryptanalysis target |
| `symlab/analysis.py` | DDT/LAT, nonlinearity, avalanche, chi-square & monobit tests, ECB leakage, **automatic differential-characteristic search + last-round key recovery** | Cryptanalysis & evaluation |
| `symlab/bench.py` | Throughput comparison | Performance evaluation |
| `cli.py` | Command-line interface for everything | — |
| `tests/` | Official test vectors (FIPS-197, RFC 8439, Speck paper) + attack test | Verification |

## 2. Requirements

- **Python 3.9 or newer** (check: `python3 --version`). Works on Windows, macOS, Linux.
- **No packages are required** for the core project (standard library only).
- Optional: `pip install -r requirements.txt` → `matplotlib` (plots for your report) and `cryptography` (extra AES cross-check test).

## 3. Setup

```bash
cd symcrypto-lab
python3 -m venv .venv                     # optional but recommended
source .venv/bin/activate                 # Windows: .venv\Scripts\activate
pip install -r requirements.txt           # optional extras (plots)
```

## 4. How to run

**Everything in one go** (saves a log to `results/run_log.txt`):
```bash
bash run_all.sh          # Windows: use Git Bash/WSL, or run the commands below one by one
```

**Individual commands**
```bash
python3 cli.py selftest                       # or: python3 -m unittest discover -s tests -v
python3 cli.py analyze sbox                   # DDT/LAT, nonlinearity of AES & PRESENT S-boxes
python3 cli.py analyze avalanche --trials 50  # diffusion of AES, Speck, ChaCha(by rounds)
python3 cli.py analyze ecb-demo               # why ECB leaks patterns
python3 cli.py analyze random                 # chi-square / monobit on keystream
python3 cli.py analyze attack --rounds 4 --seed 7   # differential key-recovery on toy SPN
python3 cli.py analyze plots                  # saves PNGs in results/
python3 cli.py bench                          # speed comparison
```

**Encrypt / decrypt a file**
```bash
python3 cli.py encrypt notes.txt -a aes-ctr        # also: chacha20, speck-ctr  → notes.txt.syml
python3 cli.py decrypt notes.txt.syml -o notes_back.txt
```
You'll be prompted for a password (or set `SYML_PASSWORD`). Wrong password or any modified byte ⇒ `authentication failed`.

## 5. Expected output (real run)

```
AES      differential_uniformity 4, nonlinearity 112, max_abs_LAT 16
PRESENT  differential_uniformity 4, nonlinearity 4
AES-128 avalanche mean=0.5005      Speck mean=0.5004
ChaCha avalanche: 2 rounds→0.34, 4 rounds→0.50 ... 20 rounds→0.50
ECB repeated blocks: 31   |   CTR repeated blocks: 0
[*] Differential attack on 4-round toy SPN
  characteristic: 0x0007 -> 0x0033  prob ~ 2^-8.0
  last-round key nibble 0: recovered 3  true 3
  last-round key nibble 1: recovered a  true a
  RESULT: KEY BITS RECOVERED
```
All 11 unit tests pass (`OK`).

## 6. How the attack works (for your viva/report)

1. Build the **DDT** of the S-box; it shows which input XOR-differences lead to which output differences with high probability.
2. **Beam-search** a multi-round *differential characteristic* `Δin → Δout` over r−1 rounds, tracking probability.
3. Collect chosen-plaintext pairs `(P, P⊕Δin)`, keep only pairs whose ciphertext difference is zero in S-boxes that should be inactive (**filtering**).
4. For each active S-box of the last round, **guess 4 key bits**, partially decrypt both ciphertexts through the inverse S-box, and count how often the expected `Δout` appears. The right guess gets a clearly higher count.
5. Result: last-round subkey bits recovered with ≈2^8 pairs instead of 2^16 brute force → demonstrates why designers bound the best differential probability and choose enough rounds (the "wide trail" idea behind AES).

## 7. Project structure
```
symcrypto-lab/
├── README.md  requirements.txt  Makefile  run_all.sh  cli.py
├── symlab/   (aes, chacha20, speck, modes, container, toy_spn, analysis, bench)
├── tests/    test_vectors.py
├── docs/     REPORT.md (report template with results)  THEORY.md (background + references)
├── scripts/  (put your own experiments here)
└── results/  (logs & plots are written here)
```

## 8. Ideas to extend (for higher marks)
- Increase `--rounds` to 5–6 and show the attack's required data growing exponentially.
- Add a **linear cryptanalysis** module using the LAT already computed.
- Implement **GCM / Poly1305** (authenticated encryption) and compare with Encrypt-then-MAC.
- Add a **reduced-round ChaCha/Speck distinguisher** (differential bias search).
- Add related-key or **meet-in-the-middle** demo on double encryption.
- Compare against `cryptography` library speed.

## 9. Troubleshooting
| Problem | Fix |
|---|---|
| `python3: command not found` (Windows) | use `python` or `py -3` |
| `No module named matplotlib` | `pip install matplotlib` or skip `analyze plots` |
| Attack says "failed" | use another `--seed` or more pairs; it is statistical |
| `run_all.sh` won't run on Windows | use Git Bash/WSL or run commands from §4 manually |
