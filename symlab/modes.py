"""Modes of operation over any object with encrypt_block/decrypt_block (16-byte blocks)."""

def pkcs7_pad(data: bytes, bs: int = 16) -> bytes:
    n = bs - len(data) % bs
    return data + bytes([n]) * n

def pkcs7_unpad(data: bytes, bs: int = 16) -> bytes:
    if not data or len(data) % bs:
        raise ValueError("bad padding length")
    n = data[-1]
    if n < 1 or n > bs or data[-n:] != bytes([n]) * n:
        raise ValueError("bad padding")
    return data[:-n]

def ctr_xcrypt(cipher, nonce: bytes, data: bytes) -> bytes:
    """CTR: counter block = 8-byte nonce || 64-bit big-endian counter. Encrypt == decrypt."""
    if len(nonce) != 8:
        raise ValueError("CTR nonce must be 8 bytes")
    out = bytearray()
    for i in range(0, len(data), 16):
        ks = cipher.encrypt_block(nonce + (i // 16).to_bytes(8, "big"))
        out += bytes(a ^ b for a, b in zip(data[i:i + 16], ks))
    return bytes(out)

def cbc_encrypt(cipher, iv: bytes, data: bytes) -> bytes:
    data, prev, out = pkcs7_pad(data), iv, bytearray()
    for i in range(0, len(data), 16):
        prev = cipher.encrypt_block(bytes(a ^ b for a, b in zip(data[i:i + 16], prev)))
        out += prev
    return bytes(out)

def cbc_decrypt(cipher, iv: bytes, data: bytes) -> bytes:
    prev, out = iv, bytearray()
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        out += bytes(a ^ b for a, b in zip(cipher.decrypt_block(blk), prev))
        prev = blk
    return pkcs7_unpad(bytes(out))

def ecb_encrypt(cipher, data: bytes) -> bytes:
    """ECB, included ONLY to demonstrate why it is insecure (see `analyze ecb-demo`)."""
    data = pkcs7_pad(data)
    return b"".join(cipher.encrypt_block(data[i:i + 16]) for i in range(0, len(data), 16))
