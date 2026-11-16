"""Authenticated file container: PBKDF2 -> cipher (CTR/ChaCha20) -> Encrypt-then-MAC (HMAC-SHA256).

Format: MAGIC(5) | algo(1) | salt(16) | nonce(8 or 12) | ciphertext | tag(32)
"""
import hashlib, hmac, os
from .aes import AES
from .speck import Speck128
from .chacha20 import chacha20_xor
from .modes import ctr_xcrypt

MAGIC = b"SYML1"
ALGOS = {"aes-ctr": 1, "chacha20": 2, "speck-ctr": 3}
ID2ALGO = {v: k for k, v in ALGOS.items()}
NONCE_LEN = {"aes-ctr": 8, "chacha20": 12, "speck-ctr": 8}
ITER = 200_000

def _keys(password: str, salt: bytes):
    km = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITER, 64)
    return km[:32], km[32:]

def _stream(algo, enc_key, nonce, data):
    if algo == "aes-ctr":
        return ctr_xcrypt(AES(enc_key), nonce, data)
    if algo == "speck-ctr":
        return ctr_xcrypt(Speck128(enc_key[:16]), nonce, data)
    return chacha20_xor(enc_key, nonce, data)

def encrypt(password: str, data: bytes, algo: str = "aes-ctr") -> bytes:
    salt, nonce = os.urandom(16), os.urandom(NONCE_LEN[algo])
    ek, mk = _keys(password, salt)
    header = MAGIC + bytes([ALGOS[algo]]) + salt + nonce
    ct = _stream(algo, ek, nonce, data)
    tag = hmac.new(mk, header + ct, hashlib.sha256).digest()
    return header + ct + tag

def decrypt(password: str, blob: bytes) -> bytes:
    if blob[:5] != MAGIC:
        raise ValueError("not a SymCrypto container")
    algo = ID2ALGO[blob[5]]
    n = NONCE_LEN[algo]
    salt, nonce = blob[6:22], blob[22:22 + n]
    ct, tag = blob[22 + n:-32], blob[-32:]
    ek, mk = _keys(password, salt)
    if not hmac.compare_digest(tag, hmac.new(mk, blob[:-32], hashlib.sha256).digest()):
        raise ValueError("authentication failed (wrong password or tampered file)")
    return _stream(algo, ek, nonce, ct)
