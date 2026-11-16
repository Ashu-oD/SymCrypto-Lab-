import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from symlab.aes import AES, SBOX
from symlab.chacha20 import chacha20_block, chacha20_xor
from symlab.speck import Speck128
from symlab import modes, container, analysis
from symlab.toy_spn import ToySPN

H = bytes.fromhex

class TestAES(unittest.TestCase):
    def test_sbox(self):
        self.assertEqual((SBOX[0], SBOX[0x53], SBOX[0xFF]), (0x63, 0xED, 0x16))

    def test_fips197_all_key_sizes(self):
        pt = H("00112233445566778899aabbccddeeff")
        for key, ct in [
            ("000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"),
            ("000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191"),
            ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "8ea2b7ca516745bfeafc49904b496089")]:
            a = AES(H(key))
            self.assertEqual(a.encrypt_block(pt).hex(), ct)
            self.assertEqual(a.decrypt_block(H(ct)), pt)

    def test_crosscheck_with_cryptography_lib(self):
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes as m
        except ImportError:
            self.skipTest("cryptography not installed")
        for _ in range(20):
            k, p = os.urandom(16), os.urandom(16)
            enc = Cipher(algorithms.AES(k), m.ECB()).encryptor()
            self.assertEqual(AES(k).encrypt_block(p), enc.update(p) + enc.finalize())

class TestStream(unittest.TestCase):
    def test_chacha_block(self):
        blk = chacha20_block(bytes(range(32)), 1, H("000000090000004a00000000"))
        self.assertTrue(blk.hex().startswith("10f1e7e4d13b5915500fdd1fa32071c4"))

    def test_chacha_encrypt(self):
        key, nonce = bytes(range(32)), H("000000000000004a00000000")
        pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
        ct = chacha20_xor(key, nonce, pt, counter=1)
        self.assertTrue(ct.hex().startswith("6e2e359a2568f98041ba0728dd0d6981"))
        self.assertEqual(chacha20_xor(key, nonce, ct, counter=1), pt)

class TestSpeck(unittest.TestCase):
    def test_vector(self):
        s = Speck128(H("0f0e0d0c0b0a09080706050403020100"))
        pt, ct = H("6c617669757165207469206564616d20"), H("a65d9851797832657860fedf5c570d18")
        self.assertEqual(s.encrypt_block(pt), ct)
        self.assertEqual(s.decrypt_block(ct), pt)

class TestModes(unittest.TestCase):
    def test_roundtrip(self):
        c = AES(os.urandom(16))
        for n in (0, 1, 15, 16, 17, 100):
            d, iv, nn = os.urandom(n), os.urandom(16), os.urandom(8)
            self.assertEqual(modes.cbc_decrypt(c, iv, modes.cbc_encrypt(c, iv, d)), d)
            self.assertEqual(modes.ctr_xcrypt(c, nn, modes.ctr_xcrypt(c, nn, d)), d)

class TestContainer(unittest.TestCase):
    def test_roundtrip_and_tamper(self):
        old, container.ITER = container.ITER, 1000
        try:
            for algo in container.ALGOS:
                blob = container.encrypt("pw", b"hello symmetric world", algo)
                self.assertEqual(container.decrypt("pw", blob), b"hello symmetric world")
                with self.assertRaises(ValueError): container.decrypt("wrong", blob)
                bad = bytearray(blob); bad[30] ^= 1
                with self.assertRaises(ValueError): container.decrypt("pw", bytes(bad))
        finally:
            container.ITER = old

class TestToy(unittest.TestCase):
    def test_invertible(self):
        t = ToySPN(4, seed=1)
        for x in range(0, 65536, 997):
            self.assertEqual(t.decrypt(t.encrypt(x)), x)

    def test_differential_attack(self):
        ok = sum(analysis.differential_attack(4, seed=s, verbose=False)["success"] for s in range(3))
        self.assertGreaterEqual(ok, 2)

    def test_aes_sbox_properties(self):
        r = analysis.sbox_report(SBOX)
        self.assertEqual((r["differential_uniformity"], r["nonlinearity"]), (4, 112))

if __name__ == "__main__":
    unittest.main()
