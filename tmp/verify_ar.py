# -*- coding: utf-8 -*-
"""验证 EAP-MSCHAPv2 Success 的 Authenticator Response 公式。
基于 18:20:33 抓到的真实会话数据，分别计算：
  1) RFC 2759 §8.7 MD4 公式 (16字节 -> 32 hex)
  2) SHA1 公式 (20字节 -> 40 hex，代码注释称与 strongSwan 一致)
与 MODPKICA 实际下发的 S= 对比。"""
import hashlib
import struct

# ---- 纯 Python MD4 实现 ----
def md4(data: bytes) -> bytes:
    A, B, C, D = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
    def rol(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xffffffff

    msg = bytearray(data)
    bitlen = (len(msg) * 8) & 0xffffffffffffffff
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", bitlen)

    def F(x, y, z): return x & y | ~x & z
    def G(x, y, z): return x & y | x & z | y & z
    def H(x, y, z): return x ^ y ^ z

    for i in range(0, len(msg), 64):
        X = list(struct.unpack("<16I", bytes(msg[i:i + 64])))
        a, b, c, d = A, B, C, D
        for j in range(16):
            k, s = j, [3, 7, 11, 19][j % 4]
            a = rol((a + F(b, c, d) + X[k]) & 0xffffffff, s)
            a, b, c, d = d, a, b, c
        for j in range(16):
            k = (j % 4) * 4 + j // 4
            s = [3, 5, 9, 13][j % 4]
            a = rol((a + G(b, c, d) + X[k] + 0x5a827999) & 0xffffffff, s)
            a, b, c, d = d, a, b, c
        for j in range(16):
            k = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15][j]
            s = [3, 9, 11, 15][j % 4]
            a = rol((a + H(b, c, d) + X[k] + 0x6ed9eba1) & 0xffffffff, s)
            a, b, c, d = d, a, b, c
        A = (A + a) & 0xffffffff
        B = (B + b) & 0xffffffff
        C = (C + c) & 0xffffffff
        D = (D + d) & 0xffffffff
    return struct.pack("<4I", A, B, C, D)

def hex_to_ascii(b: bytes) -> bytes:
    return b"".join(b"%02X" % x for x in b)

# ---- 18:42:17 抓包的真实数据（修复后第二轮） ----
peer_challenge = bytes.fromhex("180ae5d98cfbd6e57aee40685b4c1ec9")
auth_challenge = bytes.fromhex("6f64fa54a6288e8dfab93340e75c6913")
nt_response    = bytes.fromhex("43b97bb65e71e6628765da9822d0480d1009e1a2f794b52d")
username       = b"admin666"
password       = b"admin666"
observed_s     = "26188FE93AA280B44362CCD693C56DEFFD7970A3"

# ---- 公式 1: RFC 2759 §8.7 (MD4) ----
password_bytes    = "admin666".encode("utf-16le")          # NT-Hash 基于 UTF-16LE
password_hash     = md4(password_bytes)                    # 16 B NT-Hash
password_hash_hex = hex_to_ascii(password_hash)            # 32 ASCII
ar_md4 = md4(hex_to_ascii(nt_response) + password_hash_hex +
             b"MAGIC SERVER TO CLIENT SIGNING ONLY" + password_hash)
print("MD4 AR   (RFC2759):", ar_md4.hex().upper(), "(%d字节)" % len(ar_md4))

# ---- 公式 2: SHA1 式 (strongSwan eap-mschapv2.c) ----
nt_hash_hash   = md4(password_hash)                        # NtHashHash = MD4(NT-Hash)
challenge_hash = hashlib.sha1(peer_challenge + auth_challenge + username).digest()[:8]
digest1        = hashlib.sha1(nt_hash_hash + nt_response +
                              b"Magic server to client signing constant").digest()
ar_sha1        = hashlib.sha1(digest1 + challenge_hash +
                              b"Pad to make it more than one iteration").digest()
print("SHA1 AR  (strongSwan):", ar_sha1.hex().upper(), "(%d字节)" % len(ar_sha1))

print()
print("MODPKICA 实际下发 S =", observed_s)
print("SHA1 公式匹配:", ar_sha1.hex().upper() == observed_s)
print("MD4 公式匹配:", ar_md4.hex().upper() == observed_s)
