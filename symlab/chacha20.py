"""ChaCha20 stream cipher (RFC 8439)."""
import struct

M32 = 0xFFFFFFFF

def _rotl(x, n):
    return ((x << n) & M32) | (x >> (32 - n))

def _qr(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & M32; s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & M32; s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & M32; s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & M32; s[b] = _rotl(s[b] ^ s[c], 7)

def chacha20_block(key: bytes, counter: int, nonce: bytes, rounds: int = 20) -> bytes:
    if len(key) != 32 or len(nonce) != 12:
        raise ValueError("key must be 32 bytes, nonce 12 bytes")
    init = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    init += list(struct.unpack("<8I", key)) + [counter & M32] + list(struct.unpack("<3I", nonce))
    s = init[:]
    for _ in range(rounds // 2):
        _qr(s, 0, 4, 8, 12); _qr(s, 1, 5, 9, 13); _qr(s, 2, 6, 10, 14); _qr(s, 3, 7, 11, 15)
        _qr(s, 0, 5, 10, 15); _qr(s, 1, 6, 11, 12); _qr(s, 2, 7, 8, 13); _qr(s, 3, 4, 9, 14)
    return struct.pack("<16I", *[(a + b) & M32 for a, b in zip(s, init)])

def chacha20_xor(key: bytes, nonce: bytes, data: bytes, counter: int = 1, rounds: int = 20) -> bytes:
    out = bytearray()
    for i in range(0, len(data), 64):
        ks = chacha20_block(key, counter + i // 64, nonce, rounds)
        out += bytes(a ^ b for a, b in zip(data[i:i + 64], ks))
    return bytes(out)
