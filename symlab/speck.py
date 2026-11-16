"""Speck128/128 lightweight ARX block cipher (NSA, 2013).
Byte convention: block = x||y, key = l0||k0 (each word 8 bytes, big-endian),
matching the word order used in the Speck paper's test vector."""

M64 = (1 << 64) - 1

def _ror(x, n): return ((x >> n) | (x << (64 - n))) & M64
def _rol(x, n): return ((x << n) | (x >> (64 - n))) & M64

class Speck128:
    block_size = 16
    ROUNDS = 32

    def __init__(self, key: bytes):
        if len(key) != 16:
            raise ValueError("Speck128/128 key must be 16 bytes")
        l = [int.from_bytes(key[:8], "big")]
        k = [int.from_bytes(key[8:], "big")]
        for i in range(self.ROUNDS - 1):
            l.append(((k[i] + _ror(l[i], 8)) & M64) ^ i)
            k.append(_rol(k[i], 3) ^ l[i + 1])
        self.rk = k

    def encrypt_block(self, block: bytes) -> bytes:
        x = int.from_bytes(block[:8], "big"); y = int.from_bytes(block[8:], "big")
        for k in self.rk:
            x = ((_ror(x, 8) + y) & M64) ^ k
            y = _rol(y, 3) ^ x
        return x.to_bytes(8, "big") + y.to_bytes(8, "big")

    def decrypt_block(self, block: bytes) -> bytes:
        x = int.from_bytes(block[:8], "big"); y = int.from_bytes(block[8:], "big")
        for k in reversed(self.rk):
            y = _ror(y ^ x, 3)
            x = _rol(((x ^ k) - y) & M64, 8)
        return x.to_bytes(8, "big") + y.to_bytes(8, "big")
