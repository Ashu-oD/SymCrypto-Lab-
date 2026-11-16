"""AES (FIPS-197) implemented from scratch. Educational: NOT constant-time."""

def _gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11B
        b >>= 1
    return r

def _rotl8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xFF

def _build_sbox():
    inv = [0] * 256
    for a in range(1, 256):
        for b in range(1, 256):
            if _gmul(a, b) == 1:
                inv[a] = b
                break
    sbox = []
    for a in range(256):
        b = inv[a]
        sbox.append(b ^ _rotl8(b, 1) ^ _rotl8(b, 2) ^ _rotl8(b, 3) ^ _rotl8(b, 4) ^ 0x63)
    return sbox

SBOX = _build_sbox()
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i

_M2 = [_gmul(i, 2) for i in range(256)]
_M3 = [_gmul(i, 3) for i in range(256)]
_M9 = [_gmul(i, 9) for i in range(256)]
_M11 = [_gmul(i, 11) for i in range(256)]
_M13 = [_gmul(i, 13) for i in range(256)]
_M14 = [_gmul(i, 14) for i in range(256)]


class AES:
    block_size = 16

    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must be 16, 24 or 32 bytes")
        self.nk = len(key) // 4
        self.nr = self.nk + 6
        self.round_keys = self._expand(key)

    def _expand(self, key):
        nk, nr = self.nk, self.nr
        w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
        rcon = 1
        for i in range(nk, 4 * (nr + 1)):
            t = w[i - 1][:]
            if i % nk == 0:
                t = t[1:] + t[:1]
                t = [SBOX[x] for x in t]
                t[0] ^= rcon
                rcon = _M2[rcon]
            elif nk > 6 and i % nk == 4:
                t = [SBOX[x] for x in t]
            w.append([a ^ b for a, b in zip(w[i - nk], t)])
        return [sum(w[4 * r:4 * r + 4], []) for r in range(nr + 1)]

    @staticmethod
    def _shift_rows(s):
        return [s[r + 4 * ((c + r) % 4)] for c in range(4) for r in range(4)]

    @staticmethod
    def _inv_shift_rows(s):
        return [s[r + 4 * ((c - r) % 4)] for c in range(4) for r in range(4)]

    @staticmethod
    def _mix(s):
        o = []
        for c in range(0, 16, 4):
            a0, a1, a2, a3 = s[c:c + 4]
            o += [_M2[a0] ^ _M3[a1] ^ a2 ^ a3, a0 ^ _M2[a1] ^ _M3[a2] ^ a3,
                  a0 ^ a1 ^ _M2[a2] ^ _M3[a3], _M3[a0] ^ a1 ^ a2 ^ _M2[a3]]
        return o

    @staticmethod
    def _inv_mix(s):
        o = []
        for c in range(0, 16, 4):
            a0, a1, a2, a3 = s[c:c + 4]
            o += [_M14[a0] ^ _M11[a1] ^ _M13[a2] ^ _M9[a3], _M9[a0] ^ _M14[a1] ^ _M11[a2] ^ _M13[a3],
                  _M13[a0] ^ _M9[a1] ^ _M14[a2] ^ _M11[a3], _M11[a0] ^ _M13[a1] ^ _M9[a2] ^ _M14[a3]]
        return o

    def encrypt_block(self, block: bytes) -> bytes:
        s = [b ^ k for b, k in zip(block, self.round_keys[0])]
        for r in range(1, self.nr):
            s = self._shift_rows([SBOX[x] for x in s])
            s = self._mix(s)
            s = [a ^ k for a, k in zip(s, self.round_keys[r])]
        s = self._shift_rows([SBOX[x] for x in s])
        return bytes(a ^ k for a, k in zip(s, self.round_keys[self.nr]))

    def decrypt_block(self, block: bytes) -> bytes:
        s = [b ^ k for b, k in zip(block, self.round_keys[self.nr])]
        for r in range(self.nr - 1, 0, -1):
            s = [INV_SBOX[x] for x in self._inv_shift_rows(s)]
            s = [a ^ k for a, k in zip(s, self.round_keys[r])]
            s = self._inv_mix(s)
        s = [INV_SBOX[x] for x in self._inv_shift_rows(s)]
        return bytes(a ^ k for a, k in zip(s, self.round_keys[0]))
