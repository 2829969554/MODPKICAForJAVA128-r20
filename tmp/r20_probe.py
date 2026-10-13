#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""r20 修复验证（直连本地 1812，新构建）：
  [A] 取完整飞行后重传 ClientHello → 必须回放【首片】（修复前回末片 → 死循环）
  [C] 重传同一空拉取片       → 必须回放【上一片】（修复前前进一格 → 跳片）
      随后用新 EAP-Id 拉取    → 必须只前进一片（不过度拦截）
  [B] 握手中收到【新的】ClientHello（不同 random）→ 必须重建握手并回新 flight（修复前回 alert+Failure）
客户端模型：回显服务器 Request 的 EAP-Identifier（RFC 3748 §4.1）。
"""
import hashlib, hmac, os, socket, struct

HOST, PORT = "127.0.0.1", 1812
SECRET = b"mytestkey"
USERNAME = b"vpn.local"
A_USERNAME, A_EAPMSG, A_MA = 1, 79, 80
TLS = 13

ID_EAP = bytes.fromhex("0200005b0130541311301106035504070c0a6e6577657220796f726b31163014060355040a0c0d4368696e"
                       "6120495420426f79733111300f060355040b0c08495420436c7562733112301006035504030c0976706e2e6c6f63616c")
NAK_EAP = bytes.fromhex("02010006030d")


def client_hello_eap(rnd=None, eap_id=2):
    """构造完整 EAP-Response/TLS 承载 ClientHello（与 iPhone 同形，random 可变）。"""
    rnd = rnd or os.urandom(32)
    suites = bytes.fromhex("00ffc02cc02bc024c023c00ac009c008c030c02fc028c027c014c013c012009d009c003d003c0035002f")
    exts = b""
    exts += bytes.fromhex("000a00080006001700180019")
    exts += bytes.fromhex("000b00020100")
    exts += bytes.fromhex("000d0012001004010201050106010403020305030603")
    exts += bytes.fromhex("000500050100000000")
    exts += bytes.fromhex("00120000")
    exts += bytes.fromhex("00170000")
    body = b"\x03\x03" + rnd + b"\x00" + struct.pack("!H", len(suites)) + suites + b"\x01\x00" \
        + struct.pack("!H", len(exts)) + exts
    msg = b"\x01" + struct.pack("!I", len(body))[1:] + body
    rec = bytes.fromhex("160301") + struct.pack("!H", len(msg)) + msg
    eap = bytes([2, eap_id, 0, 0, TLS, 0x80]) + struct.pack("!I", len(rec)) + rec
    eap = eap[:2] + struct.pack("!H", len(eap)) + eap[4:]
    return eap, rnd


def access_request(rid, eap):
    attrs = bytes([A_USERNAME, 2 + len(USERNAME)]) + USERNAME
    for i in range(0, len(eap), 253):
        c = eap[i:i + 253]
        attrs += bytes([A_EAPMSG, 2 + len(c)]) + c
    attrs += bytes([A_MA, 18]) + b"\x00" * 16
    pkt = bytes([1, rid]) + struct.pack("!H", 20 + len(attrs)) + os.urandom(16) + attrs
    ma = 20 + len(attrs) - 16
    mac = hmac.new(SECRET, pkt[:ma] + b"\x00" * 16 + pkt[ma + 16:], hashlib.md5).digest()
    return pkt[:ma] + mac + pkt[ma + 16:]


def eap_of(pkt):
    buf, i = b"", 20
    while i + 2 <= len(pkt):
        t, l = pkt[i], pkt[i + 1]
        if l < 2 or i + l > len(pkt):
            break
        if t == A_EAPMSG:
            buf += pkt[i + 2:i + l]
        i += l
    return buf or None


class C:
    def __init__(self):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.settimeout(10)
        self.rid = 1

    def send(self, eap):
        self.s.sendto(access_request(self.rid, eap), (HOST, PORT))
        self.rid = (self.rid + 1) % 256
        r = self.s.recvfrom(65535)[0]
        return eap_of(r)

    def pull(self, sid):
        """空拉取片：回显服务器 Request 的 Identifier。"""
        e = self.send(bytes([2, sid & 0xff, 0, 6, TLS, 0x00]))
        return e

    def open(self):
        self.send(ID_EAP)
        self.send(NAK_EAP)
        return self


def frag_info(e):
    return (len(e) - 5, e[5] & 0xff, e[1] & 0xff)


ok_all = True


def check(tag, cond, extra=""):
    global ok_all
    print(("  PASS " if cond else "  FAIL ") + tag + ("  " + extra if extra else ""))
    if not cond:
        ok_all = False


# ---------- A + C：同一会话 ----------
print("== [A] 取完整飞行后重传 ClientHello ==")
c = C().open()
hello, rnd0 = client_hello_eap()
f1 = c.send(hello)
print("  首片: %dB flags=0x%02x EAP-Id=%d" % frag_info(f1))
frags, sid, last = [f1], f1[1], f1
while last[5] & 0x40:
    last = c.pull(sid)
    frags.append(last)
    sid = last[1]
print("  末片: %dB flags=0x%02x EAP-Id=%d（共 %d 片）" % (frag_info(last) + (len(frags),)))
replay = c.send(hello)          # 重传同一 ClientHello（逐字节相同，含 EAP-Id）
print("  重传响应: %dB flags=0x%02x EAP-Id=%d" % frag_info(replay))
check("A 重传回放首片（非末片）", replay == f1 and replay != last)

print("== [C] 重传同一空拉取片 ==")
r1 = c.pull(sid)                # 新拉取（sid 为服务器最新 Request Id）
pull_bytes = bytes([2, sid & 0xff, 0, 6, TLS, 0x00])
r2 = c.send(pull_bytes)         # 同一 src 上再发一次同一 (EAP-Id + 数据) → 网关重传
print("  R1: %dB flags=0x%02x / R2: %dB flags=0x%02x" % (frag_info(r1)[:2] + frag_info(r2)[:2]))
check("C 重传拉取片回放上一片（未跳片）", r2 == r1)
sid2 = r1[1]
r3 = c.pull(sid2)               # 新 EAP-Id → 应前进一片
print("  R3: %dB flags=0x%02x" % frag_info(r3)[:2])
check("C 新拉取仅前进一片", r3 != r1)

# ---------- B：客户端重启（新的 ClientHello） ----------
print("== [B] 握手中收到新的 ClientHello（客户端重启）==")
c3 = C().open()
h1, _ = client_hello_eap()
a1 = c3.send(h1)
print("  第 1 次 ClientHello → %dB flags=0x%02x" % frag_info(a1)[:2])
h2, _ = client_hello_eap()      # 不同 random = 新的握手
a2 = c3.send(h2)
print("  第 2 次（重启）→ EAP code=%s type=%s %dB" % (a2[0], a2[4] if len(a2) > 4 else "-", len(a2)))
restart_ok = a2[0] == 1 and a2[4] == TLS and len(a2) > 100 and (a2[5] & 0x40) != 0
check("B 重启重建握手并回新 flight（非 alert/Failure）", restart_ok)

print()
print("RESULT=%s" % ("PASS" if ok_all else "FAIL"))
