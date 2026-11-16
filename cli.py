#!/usr/bin/env python3
"""SymCrypto Lab command-line interface."""
import argparse, getpass, os, sys, json
from symlab import container, analysis, bench
from symlab.aes import AES, SBOX as AES_SBOX
from symlab.speck import Speck128
from symlab import toy_spn

def _pw(args):
    return args.password or os.environ.get("SYML_PASSWORD") or getpass.getpass("Password: ")

def cmd_encrypt(a):
    data = open(a.input, "rb").read()
    out = a.output or a.input + ".syml"
    open(out, "wb").write(container.encrypt(_pw(a), data, a.algo))
    print(f"[+] encrypted {a.input} -> {out} ({a.algo}, PBKDF2 + HMAC-SHA256)")

def cmd_decrypt(a):
    blob = open(a.input, "rb").read()
    out = a.output or (a.input[:-5] if a.input.endswith(".syml") else a.input + ".dec")
    try:
        open(out, "wb").write(container.decrypt(_pw(a), blob))
    except ValueError as e:
        sys.exit(f"[!] {e}")
    print(f"[+] decrypted -> {out}")

def cmd_analyze(a):
    w = a.what
    if w == "sbox":
        for name, sb in (("AES", AES_SBOX), ("PRESENT", toy_spn.SBOX)):
            print(f"{name:8s}", json.dumps(analysis.sbox_report(sb)))
    elif w == "avalanche":
        t = a.trials
        for name, fn, bs in (("AES-128", AES(bytes(16)).encrypt_block, 16),
                             ("Speck128/128", Speck128(bytes(16)).encrypt_block, 16)):
            m, lo, hi, _ = analysis.avalanche(fn, bs, trials=t)
            print(f"{name:14s} mean={m:.4f} min={lo:.4f} max={hi:.4f}  (ideal 0.5)")
        print("ChaCha key-bit avalanche by rounds:")
        for r, v in analysis.avalanche_vs_rounds_chacha().items():
            print(f"  {r:2d} rounds -> {v:.4f}")
    elif w == "ecb-demo":
        print(analysis.ecb_demo())
    elif w == "random":
        from symlab.chacha20 import chacha20_xor
        ks = chacha20_xor(os.urandom(32), os.urandom(12), bytes(1 << 18))
        print(f"ChaCha20 keystream 256KiB: chi2={analysis.byte_chi_square(ks):.1f} (expect ~255), "
              f"monobit p={analysis.monobit(ks):.3f} (>0.01 ok)")
        bad = bytes(i % 7 for i in range(1 << 18))
        print(f"Biased sample (control)   : chi2={analysis.byte_chi_square(bad):.1f}, monobit p={analysis.monobit(bad):.3f}")
    elif w == "attack":
        print(f"[*] Differential attack on {a.rounds}-round toy SPN (seed={a.seed})")
        analysis.differential_attack(a.rounds, seed=a.seed)
    elif w == "plots":
        for f in analysis.make_plots("results"): print("[+] saved", f)

def cmd_bench(a):
    print(f"{'Cipher':20s} KiB/s (pure Python, {a.size // 1024} KiB)")
    for n, v in bench.run(a.size): print(f"{n:20s} {v:10.1f}")

def cmd_selftest(a):
    import subprocess
    sys.exit(subprocess.call([sys.executable, "-m", "pytest", "-q", "tests"]))

def main():
    p = argparse.ArgumentParser(description="SymCrypto Lab")
    s = p.add_subparsers(dest="cmd", required=True)
    for name, fn in (("encrypt", cmd_encrypt), ("decrypt", cmd_decrypt)):
        q = s.add_parser(name); q.add_argument("input"); q.add_argument("-o", "--output")
        q.add_argument("-p", "--password", help="(prefer prompt or SYML_PASSWORD env var)")
        if name == "encrypt": q.add_argument("-a", "--algo", choices=list(container.ALGOS), default="aes-ctr")
        q.set_defaults(fn=fn)
    q = s.add_parser("analyze"); q.add_argument("what", choices=["sbox", "avalanche", "ecb-demo", "random", "attack", "plots"])
    q.add_argument("--rounds", type=int, default=4); q.add_argument("--seed", type=int, default=7)
    q.add_argument("--trials", type=int, default=50); q.set_defaults(fn=cmd_analyze)
    q = s.add_parser("bench"); q.add_argument("--size", type=int, default=64 * 1024); q.set_defaults(fn=cmd_bench)
    q = s.add_parser("selftest"); q.set_defaults(fn=cmd_selftest)
    a = p.parse_args(); a.fn(a)

if __name__ == "__main__":
    main()
