"""16-bit toy SPN (PRESENT S-box + bit permutation) used for cryptanalysis experiments.

Round i (0..r-1): x ^= k[i]; S-box layer; bit permutation (skipped in last round)
Final: x ^= k[r].   => r+1 independent 16-bit round keys.
"""
import random

SBOX = [0xC, 5, 6, 0xB, 9, 0, 0xA, 0xD, 3, 0xE, 0xF, 8, 4, 7, 1, 2]
INV_SBOX = [SBOX.index(i) for i in range(16)]
PERM = [(i * 4) % 15 if i < 15 else 15 for i in range(16)]
INV_PERM = [PERM.index(i) for i in range(16)]

def sbox_layer(x, box=SBOX):
    return sum(box[(x >> (4 * j)) & 0xF] << (4 * j) for j in range(4))

def perm_layer(x, perm=PERM):
    out = 0
    for i in range(16):
        out |= ((x >> i) & 1) << perm[i]
    return out

class ToySPN:
    def __init__(self, rounds=4, key=None, seed=None):
        self.r = rounds
        rng = random.Random(seed)
        self.k = key if key is not None else [rng.getrandbits(16) for _ in range(rounds + 1)]

    def encrypt(self, x):
        for i in range(self.r):
            x = sbox_layer(x ^ self.k[i])
            if i < self.r - 1:
                x = perm_layer(x)
        return x ^ self.k[self.r]

    def decrypt(self, y):
        x = y ^ self.k[self.r]
        for i in range(self.r - 1, -1, -1):
            x = sbox_layer(x, INV_SBOX)
            x ^= self.k[i]
            if i > 0:
                x = perm_layer(x, INV_PERM)
        return x
