# SymCrypto Lab — Project Report
**Topic:** IACR Transactions on Symmetric Cryptology (symmetric primitives & their cryptanalysis)
**Name / Roll no.:** ________  **Guide:** ________  **Date:** ________

## 1. Abstract
This project implements AES, ChaCha20 and Speck128/128 from scratch, verifies them against official test vectors, builds an authenticated file-encryption tool (PBKDF2 + Encrypt-then-MAC), and evaluates symmetric primitives through S-box analysis, avalanche and randomness tests, and a working differential cryptanalysis of a reduced toy SPN.

## 2. Introduction & Motivation
Symmetric cryptography protects most data in transit and at rest. IACR ToSC publishes work on designing and breaking such primitives. Understanding both sides—construction and attack—is the goal.

## 3. Objectives
1. Implement standard primitives correctly (vectors from FIPS-197, RFC 8439, Speck paper).
2. Build a secure-by-construction encryption container.
3. Quantify S-box and diffusion quality.
4. Demonstrate a differential attack on a weak (toy, 4-round) cipher.
5. Compare performance.

## 4. Design / Architecture
(Insert block diagram: `cli.py → container → {AES-CTR | ChaCha20 | Speck-CTR} → HMAC`; `analysis → {S-box, avalanche, randomness, attack}`.)

Container format: `MAGIC | algo | salt16 | nonce | ciphertext | HMAC-SHA256`; key = PBKDF2-HMAC-SHA256 (200 000 iterations) split into encryption and MAC keys.

## 5. Implementation summary
See README §1 for the module table.

## 6. Results (from `run_all.sh`)
| Experiment | Result | Interpretation |
|---|---|---|
| Test vectors | 11/11 tests pass | Implementations correct |
| AES S-box | diff. uniformity 4, nonlinearity 112 | Optimal for 8-bit invertible S-box (inverse map) |
| PRESENT S-box | diff. uniformity 4 (p=2⁻²), nonlinearity 4 | Good 4-bit S-box but weak vs 8-bit; needs many rounds |
| Avalanche AES / Speck | ≈0.500 / ≈0.500 | Full diffusion |
| ChaCha avalanche vs rounds | 2→0.34, 4→0.50, 20→0.50 | Diffusion saturates after ~4 rounds; 20 gives security margin |
| ECB vs CTR | 31 vs 0 repeated blocks | ECB leaks patterns |
| Keystream χ², monobit | χ²≈235 (expected ≈255), p=0.26 | Passes; biased control fails |
| Differential attack (4-round toy SPN) | char. 0x0007→0x0033, p≈2⁻⁸; 2 key nibbles recovered with 3072 chosen pairs | Toy cipher broken far below 2¹⁶ exhaustive search |
| Throughput (pure Python, KiB/s) | Speck ≈550, AES-128 ≈375, ChaCha ≈360, AES-256 ≈195 | ARX is cheap in software; interpreter overhead dominates |

(Insert `results/ddt_present.png` and `results/chacha_avalanche.png`.)

## 7. Security discussion
- CTR nonce reuse ⇒ keystream reuse ⇒ plaintext XOR leaks; each file uses a fresh random nonce and salt.
- Authentication prevents bit-flipping (CTR is malleable); HMAC verified in constant time *before* decrypting.
- Limitations: pure-Python → timing side channels (table-lookup AES); no hardware acceleration; toy-cipher results do not transfer directly to full AES.

## 8. Conclusion & Future work
Linear cryptanalysis module, GCM/Poly1305, reduced-round ChaCha/Speck distinguishers, integral attack on 4-round AES.

## 9. References
See `docs/THEORY.md`.
