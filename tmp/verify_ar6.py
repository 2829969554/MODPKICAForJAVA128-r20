# -*- coding: utf-8 -*-
"""终验：19:45:55 成功会话——用线上真实字节复算 AuthenticatorResponse，
与 MODPKICA 实际下发 S=3A69856543DAD97E58393C72717BE566748E192F 比对。"""
import hashlib, struct

def md4(data: bytes) -> bytes:
    A, B, C, D = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
    def rol(x, n): return ((x << n) | (x >> (32 - n))) & 0xffffffff
    msg = bytearray(data)
    bitlen = (len(msg) * 8) & 0xffffffffffffffff
    msg.append(0x80)
    while len(msg) % 64 != 56: msg.append(0)
    msg += struct.pack("<Q", bitlen)
    def F(x, y, z): return x & y | ~x & z
    def G(x, y, z): return x & y | x & z | y & z
    def H(x, y, z): return x ^ y ^ z
    for i in range(0, len(msg), 64):
        X = list(struct.unpack("<16I", bytes(msg[i:i+64])))
        a, b, c, d = A, B, C, D
        for j in range(16):
            k, s = j, [3, 7, 11, 19][j % 4]
            a = rol((a + F(b, c, d) + X[k]) & 0xffffffff, s); a, b, c, d = d, a, b, c
        for j in range(16):
            k = (j % 4) * 4 + j // 4; s = [3, 5, 9, 13][j % 4]
            a = rol((a + G(b, c, d) + X[k] + 0x5a827999) & 0xffffffff, s); a, b, c, d = d, a, b, c
        for j in range(16):
            k = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15][j]; s = [3, 9, 11, 15][j % 4]
            a = rol((a + H(b, c, d) + X[k] + 0x6ed9eba1) & 0xffffffff, s); a, b, c, d = d, a, b, c
        A = (A + a) & 0xffffffff; B = (B + b) & 0xffffffff
        C = (C + c) & 0xffffffff; D = (D + d) & 0xffffffff
    return struct.pack("<4I", A, B, C, D)

MAGIC1 = b"Magic server to client signing constant"
MAGIC2 = b"Pad to make it do more than one iteration"

# ---- 19:45:55 成功会话（MODPKICA 修复后）----
peer = bytes.fromhex("96ee6d82a7c195fe0b8d5fa54efc421a")
auth = bytes.fromhex("f42f41fae6b3f5e7e2a8883d98211669")
nt   = bytes.fromhex("dd6b4afc0887957f6c2908328c1ab51d903a53a771ff2eb7")
sent = "3A69856543DAD97E58393C72717BE566748E192F"

ph = md4("admin666".encode("utf-16le"))
phh = md4(ph)
d1 = hashlib.sha1(phh + nt + MAGIC1).digest()
ch = hashlib.sha1(peer + auth + b"admin666").digest()[:8]
d2 = hashlib.sha1(d1 + ch + MAGIC2).digest()
computed = d2.hex().upper()
print("MODPKICA 实际下发 S =", sent)
print("RFC2759 复算     S =", computed)
print("匹配:", computed == sent)
