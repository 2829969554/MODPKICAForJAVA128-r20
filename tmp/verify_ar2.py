# -*- coding: utf-8 -*-
"""决定性验证：RFC 2759 §8.8 AuthenticatorResponse 公式复算
两轮真实会话（同一 Windows 客户端）：
  A. FreeRADIUS 后端 19:07:31 —— 成功连接（Windows 接受其 S=）
  B. MODPKICA 后端 19:35:16 —— 失败 645（Windows 拒绝其 S=）
公式：AR = SHA1(PasswordHash, NTResponse, Magic1)[0:20]，PasswordHash=MD4(UTF16LE(password))
若 A 复算命中 FreeRADIUS 下发的 S=，而 B 复算不命中 MODPKICA 下发的 S= → 铁证：MODPKICA 的
AuthenticatorResponse 计算错误，Windows 校验失败丢弃 Success → 645。
同时复算 strongSwan 风格公式（verify_ar.py 之前的实现）做对照。"""
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
MAGIC2 = b"Pad to make it more than one iteration"

def rfc2759_ar(password: str, nt_response: bytes) -> str:
    """RFC 2759 §8.8: AR = SHA1(PasswordHash, NTResponse, Magic1)"""
    ph = md4(password.encode("utf-16le"))
    return hashlib.sha1(ph + nt_response + MAGIC1).digest().hex().upper()

def strongswan_ar(password: str, peer_challenge: bytes, auth_challenge: bytes,
                  nt_response: bytes, username: bytes) -> str:
    """verify_ar.py 之前用的 strongSwan 风格公式"""
    ph = md4(password.encode("utf-16le"))
    phh = md4(ph)
    ch = hashlib.sha1(peer_challenge + auth_challenge + username).digest()[:8]
    d1 = hashlib.sha1(phh + nt_response + MAGIC1).digest()
    return hashlib.sha1(d1 + ch + MAGIC2).digest().hex().upper()

print("=" * 78)
print("A. FreeRADIUS 19:07:31（成功）")
peer  = bytes.fromhex("89a8becc51e218bc8bc966eed067e2a1")
authc = bytes.fromhex("0fc524e7c7238006459593fdf52505ae")
nt    = bytes.fromhex("b588fbcf50ec764de5366a06c60c0466488444fad2d9ff22")
user  = b"admin666"
sent_s = "F54234FC7F1AB3B62B965B94FD633F1F367B07E0"
print("  FreeRADIUS 下发 S =", sent_s)
print("  RFC2759 复算     =", rfc2759_ar("admin666", nt))
print("  strongSwan 复算  =", strongswan_ar("admin666", peer, authc, nt, user))

print("=" * 78)
print("B. MODPKICA 19:35:16（失败）")
peer  = bytes.fromhex("ba59b71730216f89393f7adafacad5c1")
authc = bytes.fromhex("eaf6ce03c79d17915f54b95c5dc353a1")
nt    = bytes.fromhex("abcfb108e9f3952df5455259c37835747c1fae787ced6b60")
user  = b"admin666"
sent_s = "6DF6C351EB49A0FDF219F584B6792C97C6D550DB"
print("  MODPKICA 下发 S  =", sent_s)
print("  RFC2759 复算     =", rfc2759_ar("admin666", nt))
print("  strongSwan 复算  =", strongswan_ar("admin666", peer, authc, nt, user))
