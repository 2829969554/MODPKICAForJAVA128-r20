# -*- coding: utf-8 -*-
"""修正 Magic2 后重算：RFC §9.2 示例 + FreeRADIUS + MODPKICA。"""
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
print("Magic1 len:", len(MAGIC1), "Magic2 len:", len(MAGIC2))

def gen_ar(password: str, nt_response: bytes, peer: bytes, auth: bytes, username: bytes) -> str:
    ph = md4(password.encode("utf-16le"))
    phh = md4(ph)
    d1 = hashlib.sha1(phh + nt_response + MAGIC1).digest()
    ch = hashlib.sha1(peer + auth + username).digest()[:8]
    d2 = hashlib.sha1(d1 + ch + MAGIC2).digest()
    return d2.hex().upper()

print()
print("=== RFC 2759 §9.2 示例（期望 S=407A5589115FD0D6209F510FE9C04566932CDA56）===")
print("  我的实现:", gen_ar("clientPass",
      bytes.fromhex("82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF"),
      bytes.fromhex("21402324255E262A28295F2B3A337C7E"),
      bytes.fromhex("5B5D7C7D7B3F2F3E3C2C602132262628"), b"User"))

print()
print("=== FreeRADIUS 19:07:31（下发 S=F54234FC7F1AB3B62B965B94FD633F1F367B07E0）===")
print("  我的实现:", gen_ar("admin666",
      bytes.fromhex("b588fbcf50ec764de5366a06c60c0466488444fad2d9ff22"),
      bytes.fromhex("89a8becc51e218bc8bc966eed067e2a1"),
      bytes.fromhex("0fc524e7c7238006459593fdf52505ae"), b"admin666"))

print()
print("=== MODPKICA 19:35:16（下发 S=6DF6C351EB49A0FDF219F584B6792C97C6D550DB）===")
print("  我的实现:", gen_ar("admin666",
      bytes.fromhex("abcfb108e9f3952df5455259c37835747c1fae787ced6b60"),
      bytes.fromhex("ba59b71730216f89393f7adafacad5c1"),
      bytes.fromhex("eaf6ce03c79d17915f54b95c5dc353a1"), b"admin666"))
