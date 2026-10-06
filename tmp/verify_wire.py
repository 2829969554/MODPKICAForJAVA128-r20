# -*- coding: utf-8 -*-
"""从网关抓包文件程序化提取 19:45:55 / 20:14:51 会话的成功链路，复算 S= 并与线上值比对。"""
import hashlib, struct, re

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

def gen_ar(password: str, nt_response: bytes, peer: bytes, auth: bytes, username: bytes) -> str:
    ph = md4(password.encode("utf-16le"))
    phh = md4(ph)
    d1 = hashlib.sha1(phh + nt_response + MAGIC1).digest()
    ch = hashlib.sha1(peer + auth + username).digest()[:8]
    return hashlib.sha1(d1 + ch + MAGIC2).digest().hex().upper()

def parse_eap_mschap(hexstr: str):
    """EAP-Message 十六进制 -> 提取 (auth_challenge 或 peer/nt/name)。"""
    b = bytes.fromhex(hexstr)
    if len(b) < 5 or b[4] != 0x1a:
        return None
    p = 5  # 越过 EAP code/id/len/type
    if len(b) < p + 1:
        return None
    op = b[p]; p += 1
    if op == 3 and len(b) <= p:   # 客户端 Success 确认（只有 OpCode）
        return ("success_ack",)
    if len(b) < p + 4:
        return None
    mid = b[p]; p += 1
    mslen = (b[p] << 8) | b[p+1]; p += 2
    if op == 3:  # Success: 无 Value-Size，Message 紧随 MS-Length
        msg = b[p:].decode("latin1")
        return ("success", mid, msg)
    vsz = b[p]; p += 1
    if op == 1:  # Challenge
        challenge = b[p:p+16]
        name = b[p+16:].decode("latin1") if p+16 <= len(b) else ""
        return ("challenge", mid, challenge, name)
    if op == 2:  # Response
        peer = b[p:p+16]; p += 16
        reserved = b[p:p+8]; p += 8
        nt = b[p:p+24]; p += 24
        flags = b[p]; p += 1
        name = b[p:].decode("latin1")
        return ("response", mid, peer, nt, name)
    return None

def extract_session(lines, ts):
    """按时间戳切出一个会话的 挑战/响应/Success。"""
    sess = {}
    for ln in lines:
        if not ts in ln:
            continue
        m = re.search(r"EAP-Message\[(\d+)\] = ([0-9a-f]+)", ln)
        if not m:
            continue
        r = parse_eap_mschap(m.group(2))
        if r is None:
            continue
        if r[0] == "challenge" and "challenge" not in sess:
            sess["challenge"] = r
        elif r[0] == "response" and "response" not in sess:
            sess["response"] = r
        elif r[0] == "success":
            sess["success"] = r
    return sess

txt = open("radius_capture_local.txt", "r", encoding="utf-8", errors="replace").read().splitlines()
for ts, label in [("19:45:55", "19:45:55"), ("20:14:5", "20:14:51")]:
    s = extract_session(txt, ts)
    if "challenge" in s and "response" in s and "success" in s:
        _, _, auth, _ = s["challenge"]
        _, _, peer, nt, name = s["response"]
        _, _, msg = s["success"]
        m = re.match(r"S=([0-9A-F]{40})", msg)
        if m:
            sent = m.group(1)
            computed = gen_ar("admin666", nt, peer, auth, name.encode("latin1"))
            print("===", label, "===")
            print("  线上 S =", sent)
            print("  复算 S =", computed)
            print("  匹配:", sent == computed)
        else:
            print("===", label, "=== Success 无 S=:", msg[:60])
    else:
        print("===", label, "=== 未齐:", list(s.keys()))
