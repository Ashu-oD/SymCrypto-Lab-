"""Cryptanalysis & statistical-evaluation tools (educational, reduced/toy targets only)."""
import os, random, math, time
from . import toy_spn as T
from .aes import AES, SBOX as AES_SBOX
from .speck import Speck128
from .chacha20 import chacha20_block

def popcount(x): return bin(x).count("1")

# ---------------------------------------------------------------- S-box properties
def ddt(sbox):
    n = len(sbox)
    t = [[0] * n for _ in range(n)]
    for a in range(n):
        for x in range(n):
            t[a][sbox[x] ^ sbox[x ^ a]] += 1
    return t

def lat(sbox):
    """Linear approximation table: entry = #{x: a.x == b.S(x)} - n/2."""
    n = len(sbox)
    t = [[0] * n for _ in range(n)]
    for a in range(n):
        for b in range(n):
            c = sum(1 for x in range(n) if popcount(a & x) % 2 == popcount(b & sbox[x]) % 2)
            t[a][b] = c - n // 2
    return t

def sbox_report(sbox):
    n = len(sbox)
    d, l = ddt(sbox), lat(sbox)
    diff_unif = max(d[a][b] for a in range(1, n) for b in range(n))
    max_lin = max(abs(l[a][b]) for a in range(n) for b in range(1, n))
    bits = n.bit_length() - 1
    return {"size": n, "differential_uniformity": diff_unif,
            "max_diff_prob": diff_unif / n,
            "max_abs_LAT": max_lin, "nonlinearity": n // 2 - max_lin,
            "max_linear_bias": max_lin / n, "is_bijective": len(set(sbox)) == n, "bits": bits}

# ---------------------------------------------------------------- Avalanche / SAC
def avalanche(encrypt_block, block_bytes, trials=200, seed=0):
    """Flip each input bit; return mean fraction of output bits flipped (ideal 0.5)."""
    rng = random.Random(seed)
    nbits = block_bytes * 8
    per_bit = [0.0] * nbits
    for _ in range(trials):
        pt = bytes(rng.getrandbits(8) for _ in range(block_bytes))
        base = encrypt_block(pt)
        for b in range(nbits):
            m = bytearray(pt); m[b // 8] ^= 1 << (7 - b % 8)
            c = encrypt_block(bytes(m))
            per_bit[b] += sum(popcount(x ^ y) for x, y in zip(base, c)) / nbits
    per_bit = [v / trials for v in per_bit]
    return sum(per_bit) / nbits, min(per_bit), max(per_bit), per_bit

def avalanche_vs_rounds_chacha(trials=100, seed=0):
    """Diffusion of ChaCha as function of round count (ties to reduced-round analysis)."""
    rng = random.Random(seed)
    res = {}
    for rounds in (2, 4, 6, 8, 12, 20):
        tot = cnt = 0
        for _ in range(trials):
            key = bytes(rng.getrandbits(8) for _ in range(32)); nonce = bytes(12)
            k2 = bytearray(key); b = rng.randrange(256); k2[b // 8] ^= 1 << (b % 8)
            x, y = chacha20_block(key, 0, nonce, rounds), chacha20_block(bytes(k2), 0, nonce, rounds)
            tot += sum(popcount(p ^ q) for p, q in zip(x, y)); cnt += 512
        res[rounds] = tot / cnt
    return res

# ---------------------------------------------------------------- Randomness tests
def byte_chi_square(data):
    exp = len(data) / 256
    cnt = [0] * 256
    for b in data: cnt[b] += 1
    return sum((c - exp) ** 2 / exp for c in cnt)   # ~255 +- 22.6 for random data

def monobit(data):
    ones = sum(popcount(b) for b in data); n = len(data) * 8
    s = abs(2 * ones - n) / math.sqrt(n)
    return math.erfc(s / math.sqrt(2))               # p-value, want > 0.01

# ---------------------------------------------------------------- ECB demo
def ecb_demo(n_blocks=64):
    from .modes import ecb_encrypt, ctr_xcrypt
    c = AES(os.urandom(16))
    pt = (b"ATTACK AT DAWN!!" * (n_blocks // 2)) + os.urandom(16 * (n_blocks // 2))
    def dup(ct): 
        blocks = [ct[i:i + 16] for i in range(0, len(ct), 16)]
        return len(blocks) - len(set(blocks))
    return {"ecb_repeated_blocks": dup(ecb_encrypt(c, pt)),
            "ctr_repeated_blocks": dup(ctr_xcrypt(c, os.urandom(8), pt))}

# ---------------------------------------------------------------- Differential cryptanalysis of ToySPN
def find_characteristic(rounds, beam=300, top_per_nibble=4):
    """Beam-search a good differential characteristic through `rounds` S-layer+perm steps."""
    D = ddt(T.SBOX)
    opts = {a: sorted(((b, D[a][b] / 16) for b in range(16) if D[a][b]), key=lambda t: -t[1])[:top_per_nibble]
            for a in range(1, 16)}
    cur = {(a << (4 * j)): 1.0 for j in range(4) for a in range(1, 16)}
    start = dict(cur)
    for _ in range(rounds):
        nxt = {}
        for d, p in cur.items():
            outs = [(0, p)]
            for j in range(4):
                a = (d >> (4 * j)) & 0xF
                if a:
                    outs = [(o | (b << (4 * j)), q * pb) for o, q in outs for b, pb in opts[a]]
            for o, q in outs:
                o = T.perm_layer(o)
                if q > nxt.get(o, 0): nxt[o] = q
        cur = dict(sorted(nxt.items(), key=lambda kv: -kv[1])[:beam])
    out_diff, prob = max(cur.items(), key=lambda kv: kv[1])
    # recover which input produced it by re-search (simple: try all starts)
    best_in = None
    for din in start:
        c2 = {din: 1.0}
        for _ in range(rounds):
            n2 = {}
            for d, p in c2.items():
                outs = [(0, p)]
                for j in range(4):
                    a = (d >> (4 * j)) & 0xF
                    if a:
                        outs = [(o | (b << (4 * j)), q * pb) for o, q in outs for b, pb in opts[a]]
                for o, q in outs:
                    o = T.perm_layer(o)
                    if q > n2.get(o, 0): n2[o] = q
            c2 = n2
        if abs(c2.get(out_diff, 0) - prob) < 1e-12:
            best_in = din; break
    return best_in, out_diff, prob

def differential_attack(rounds=4, seed=None, n_pairs=None, verbose=True):
    """Chosen-plaintext last-round subkey recovery on a `rounds`-round ToySPN."""
    cipher = T.ToySPN(rounds, seed=seed)
    d_in, d_out, p = find_characteristic(rounds - 1)
    if n_pairs is None:
        n_pairs = int(min(max(12 / p, 3000), 80000))
    rng = random.Random(seed)
    active = [j for j in range(4) if (d_out >> (4 * j)) & 0xF]
    inactive_mask = sum(0xF << (4 * j) for j in range(4) if j not in active)
    pairs = []
    for _ in range(n_pairs):
        x = rng.getrandbits(16)
        c1, c2 = cipher.encrypt(x), cipher.encrypt(x ^ d_in)
        if (c1 ^ c2) & inactive_mask == 0:
            pairs.append((c1, c2))
    recovered, truth = {}, {}
    for j in active:
        want = (d_out >> (4 * j)) & 0xF
        scores = []
        for g in range(16):
            s = sum(1 for c1, c2 in pairs
                    if T.INV_SBOX[((c1 >> (4 * j)) & 0xF) ^ g] ^ T.INV_SBOX[((c2 >> (4 * j)) & 0xF) ^ g] == want)
            scores.append(s)
        recovered[j] = max(range(16), key=lambda g: scores[g])
        truth[j] = (cipher.k[rounds] >> (4 * j)) & 0xF
    ok = all(recovered[j] == truth[j] for j in active)
    info = {"rounds": rounds, "input_diff": d_in, "output_diff": d_out, "char_prob": p,
            "pairs_used": n_pairs, "pairs_kept": len(pairs), "active_nibbles": active,
            "recovered": recovered, "true": truth, "success": ok}
    if verbose:
        print(f"  characteristic: {d_in:#06x} -> {d_out:#06x}  prob ~ 2^{math.log2(p):.1f}")
        print(f"  pairs: {n_pairs} generated, {len(pairs)} kept after filtering")
        for j in active:
            print(f"  last-round key nibble {j}: recovered {recovered[j]:x}  true {truth[j]:x}")
        print("  RESULT:", "KEY BITS RECOVERED" if ok else "failed (try more pairs / another seed)")
    return info

# ---------------------------------------------------------------- Plots (optional)
def make_plots(outdir="results"):
    try:
        import matplotlib; matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed; skipping plots (pip install matplotlib)"); return []
    os.makedirs(outdir, exist_ok=True); files = []
    d = ddt(T.SBOX)
    plt.figure(figsize=(5, 4.5)); plt.imshow(d, cmap="viridis"); plt.colorbar()
    plt.title("DDT of PRESENT S-box"); plt.xlabel("output diff"); plt.ylabel("input diff")
    f = os.path.join(outdir, "ddt_present.png"); plt.savefig(f, dpi=130, bbox_inches="tight"); plt.close(); files.append(f)
    res = avalanche_vs_rounds_chacha(60)
    plt.figure(figsize=(5, 3.5)); plt.plot(list(res), list(res.values()), "o-"); plt.axhline(.5, ls="--", c="gray")
    plt.xlabel("ChaCha rounds"); plt.ylabel("mean output bit-flip ratio"); plt.title("ChaCha avalanche vs rounds")
    f = os.path.join(outdir, "chacha_avalanche.png"); plt.savefig(f, dpi=130, bbox_inches="tight"); plt.close(); files.append(f)
    return files
