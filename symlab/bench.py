import os, time
from .aes import AES
from .speck import Speck128
from .chacha20 import chacha20_xor
from .modes import ctr_xcrypt

def run(size=64 * 1024):
    data = os.urandom(size); rows = []
    tests = {
        "AES-128-CTR": lambda: ctr_xcrypt(AES(os.urandom(16)), os.urandom(8), data),
        "AES-256-CTR": lambda: ctr_xcrypt(AES(os.urandom(32)), os.urandom(8), data),
        "Speck128/128-CTR": lambda: ctr_xcrypt(Speck128(os.urandom(16)), os.urandom(8), data),
        "ChaCha20": lambda: chacha20_xor(os.urandom(32), os.urandom(12), data),
    }
    for name, fn in tests.items():
        t = time.perf_counter(); fn(); dt = time.perf_counter() - t
        rows.append((name, size / dt / 1024))
    return rows
