# Background & References

**Scope of IACR ToSC:** design and analysis of block ciphers, stream ciphers, hash functions, MACs, AEAD schemes, modes of operation, lightweight primitives, and cryptanalytic techniques (differential, linear, integral, algebraic, side-channel-aware design).

## Key concepts used
- **Confusion & diffusion** (Shannon, 1949): S-boxes give non-linearity, linear layers spread local changes.
- **SPN vs ARX:** AES/PRESENT use S-boxes + linear layer; ChaCha/Speck use only Add-Rotate-XOR.
- **Differential cryptanalysis** (Biham–Shamir, 1990): exploits non-uniform XOR-difference propagation. DDT entry / 2^n = probability.
- **Linear cryptanalysis** (Matsui, 1993): exploits biased linear relations of plaintext/ciphertext/key bits; bias read from the LAT.
- **Wide Trail Strategy** (Daemen–Rijmen): AES's ShiftRows+MixColumns guarantee ≥25 active S-boxes over 4 rounds, bounding differential/linear probability.
- **Avalanche / SAC:** flipping one input bit should flip each output bit with probability ½.
- **Modes:** ECB leaks equality of blocks; CTR needs unique nonces; CBC needs unpredictable IV and is malleable → always authenticate (Encrypt-then-MAC).

## References
1. FIPS 197, *Advanced Encryption Standard*, NIST, 2001.
2. D. J. Bernstein, *ChaCha, a variant of Salsa20*, 2008; RFC 8439 (ChaCha20-Poly1305), IETF, 2018.
3. R. Beaulieu et al., *The SIMON and SPECK families of lightweight block ciphers*, ePrint 2013/404.
4. A. Bogdanov et al., *PRESENT: An Ultra-Lightweight Block Cipher*, CHES 2007.
5. E. Biham, A. Shamir, *Differential cryptanalysis of DES-like cryptosystems*, J. Cryptology 1991.
6. M. Matsui, *Linear cryptanalysis method for DES cipher*, EUROCRYPT 1993.
7. J. Daemen, V. Rijmen, *The Design of Rijndael*, Springer, 2002.
8. H. Heys, *A Tutorial on Linear and Differential Cryptanalysis*, 2002 (the toy-SPN attack is modelled on it).
9. IACR Transactions on Symmetric Cryptology — https://tosc.iacr.org
