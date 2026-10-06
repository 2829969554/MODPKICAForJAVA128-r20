# -*- coding: utf-8 -*-
"""用 RFC 2759 §9.2 官方示例验证 AuthenticatorResponse 公式实现，
再复算 FreeRADIUS/MODPKICA 两轮真实数据。"""
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

MAGIC1 = bytes.fromhex("4D617669632073657276657220746F20636C69656E74207369676E696E6720636F6E7374616E74")
MAGIC2 = bytes.fromhex("50616420746F206D616B65206974206D6F7265207468616E206F6E6520697465726174696F6E")

def gen_ar(password: str, nt_response: bytes, peer: bytes, auth: bytes, username: bytes) -> str:
    ph = md4(password.encode("utf-16le"))                    # PasswordHash
    phh = md4(ph)                                            # PasswordHashHash
    d1 = hashlib.sha1(phh + nt_response + MAGIC1).digest()
    ch = hashlib.sha1(peer + auth + username).digest()[:8]   # §8.2: Peer, Auth, User 顺序
    d2 = hashlib.sha1(d1 + ch + MAGIC2).digest()
    return d2.hex().upper()

# ---- RFC 2759 §9.2 官方示例 ----
print("=== RFC 2759 §9.2 示例（期望 S=407A5589115FD0D6209F510FE9C04566932CDA56）===")
pw = "clientPass"
peer = bytes.fromhex("21402324255E262A28295F2B3A337C7E")
auth = bytes.fromhex("5B5D7C7D7B3F2F3E3C2C602132262628")
nt = bytes.fromhex("82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF")
print("  我的实现:", gen_ar(pw, nt, peer, auth, b"User"))
print("  RFC 期望:", "407A5589115FD0D6209F510FE9C04566932CDA56")

# ---- FreeRADIUS 19:07:31（成功）----
print("=== FreeRADIUS 19:07:31（期望 S=F54234FC7F1AB3B62B965B94FD633F1F367B07E0）===")
peer = bytes.fromhex("89a8becc51e218bc8bc966eed067e2a1")
auth = bytes.fromhex("0fc524e7c7238006459593fdf52505ae")
nt = bytes.fromhex("b588fbcf50ec764de5366a06c60c0466488444fad2d9ff22")
print("  我的实现:", gen_ar("admin666", nt, peer, auth, b"admin666"))
print("  FreeRADIUS 下发:", "F54234FC7F1AB3B62B965B94FD633F1F367B07E0")

# ---- MODPKICA 19:35:16（失败）----
print("=== MODPKICA 19:35:16（期望 S=6DF6C351EB49A0FDF219F584B6792C97C6D550DB）===")
peer = bytes.fromhex("ba59b71730216f89393f7adafacad5c1")
auth = bytes.fromhex("eaf6ce03c79d17915f54b95c5dc353a1")
nt = bytes.fromhex("abcfb108e9f3952df5455259c37835747c1fae787ced6b60")
print("  我的实现:", gen_ar("admin666", nt, peer, auth, b"admin666"))
print("  MODPKICA 下发:", "6DF6C351EB49A0FDF219F584B6792C97C6D550DB")
