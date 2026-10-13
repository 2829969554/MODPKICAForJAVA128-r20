#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""EAP-TLS 抓包 + 服务端 ServerKeyExchange 签名手工验证。

流程：UDP 1812 走 EAP-TLS → 抓服务端完整飞行 → 解析 ServerHello/Certificate/ServerKeyExchange
     → 用证书里的 RSA 公钥验证 SKE 签名（TLS 1.2：SHA256(ClientHello+ServerHello+ECDHParams)）。
"""
import hashlib
import hmac
import os
import socket
import struct
import subprocess
import sys

import os
HOST, PORT = "127.0.0.1", int(os.environ.get("EAP_PORT", "1812"))
SECRET = b"mytestkey"
IDENTITY = "tls:admin666"
A_USERNAME, A_EAPMSG, A_MA = 1, 79, 80
EAP_TYPE_TLS = 13


def client_hello(offer13=False):
    rnd = os.urandom(32)
    suites = struct.pack("!HHH", 0xC02F, 0xC02B, 0x009C)
    exts = b""
    exts += struct.pack("!HH", 0x000A, 8) + struct.pack("!H", 6) + struct.pack("!HHH", 0x001D, 0x0017, 0x0018)
    exts += struct.pack("!HH", 0x000B, 2) + b"\x01\x00"
    sa = struct.pack("!HHHHH", 0x0401, 0x0501, 0x0601, 0x0403, 0x0201)
    exts += struct.pack("!HH", 0x000D, 2 + len(sa)) + struct.pack("!H", len(sa)) + sa
    exts += struct.pack("!HH", 0x0017, 0)
    if offer13:
        # 真实客户端（Windows SChannel 等）同时列出 1.3 与 1.2
        exts += struct.pack("!HH", 0x002B, 5) + bytes([4, 0x03, 0x04, 0x03, 0x03])
    body = (b"\x03\x03" + rnd + b"\x00" + struct.pack("!H", len(suites)) + suites
            + b"\x01\x00" + struct.pack("!H", len(exts)) + exts)
    msg = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return msg, bytes([0x16, 0x03, 0x01]) + struct.pack("!H", len(msg)) + msg


def build_eap(code, eap_id, etype=None, data=b""):
    if etype is None:
        return bytes([code, eap_id]) + struct.pack("!H", 4) + data
    body = bytes([etype]) + data
    return bytes([code, eap_id]) + struct.pack("!H", 4 + len(body)) + body


def access_request(rid, eap):
    ident = IDENTITY.encode()
    attrs = bytes([A_USERNAME, 2 + len(ident)]) + ident
    for i in range(0, len(eap), 253):
        c = eap[i:i + 253]
        attrs += bytes([A_EAPMSG, 2 + len(c)]) + c
    attrs += bytes([A_MA, 18]) + b"\x00" * 16
    pkt = bytes([1, rid]) + struct.pack("!H", 20 + len(attrs)) + os.urandom(16) + attrs
    ma_off = 20 + len(attrs) - 16
    mac = hmac.new(SECRET, pkt[:ma_off] + b"\x00" * 16 + pkt[ma_off + 16:], hashlib.md5).digest()
    return pkt[:ma_off] + mac + pkt[ma_off + 16:]


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


def run(offer13=False):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(4)
    state = {"rid": 7}

    def send(eap):
        sock.sendto(access_request(state["rid"], eap), (HOST, PORT))
        return sock.recvfrom(65535)[0]

    resp = send(build_eap(2, 0, 1, IDENTITY.encode()))
    print("Start:", eap_of(resp)[5:].hex())

    ch_msg, ch_rec = client_hello(offer13)
    state["rid"] = (state["rid"] + 1) % 256
    resp = send(build_eap(2, 1, EAP_TYPE_TLS, b"\x80" + struct.pack("!I", len(ch_rec)) + ch_rec))

    flight = b""
    total = None
    for _ in range(60):
        eap = eap_of(resp)
        if eap is None or len(eap) < 5 or eap[4] != EAP_TYPE_TLS:
            print("非 TLS 响应:", eap.hex() if eap else None)
            break
        d = eap[5:]
        flags = d[0]
        rest = d[1:]
        if flags & 0x80:
            total = struct.unpack("!I", rest[:4])[0]
            rest = rest[4:]
        flight += rest
        if not (flags & 0x40):
            break
        state["rid"] = (state["rid"] + 1) % 256
        resp = send(build_eap(2, 2, EAP_TYPE_TLS, b"\x00"))
    print("服务端飞行 %d 字节（声明总长 %s）" % (len(flight), total))
    return ch_msg, flight


def parse_msgs(flight):
    msgs, pos = [], 0
    while pos + 5 <= len(flight):
        rlen = struct.unpack("!H", flight[pos + 3:pos + 5])[0]
        end = pos + 5 + rlen
        p = pos + 5
        while p + 4 <= end:
            mtype = flight[p]
            mlen = struct.unpack("!I", b"\x00" + flight[p + 1:p + 4])[0]
            msgs.append((mtype, flight[p + 4:p + 4 + mlen]))
            p += 5 + mlen
        pos = end
    return msgs


def main():
    offer13 = "--tls13" in sys.argv
    ch_msg, flight = run(offer13)
    msgs = parse_msgs(flight)
    names = {2: "ServerHello", 11: "Certificate", 12: "ServerKeyExchange",
             13: "CertificateRequest", 14: "ServerHelloDone", 15: "CertificateStatus"}
    print("握手消息:", ", ".join("%s(%dB)" % (names.get(t, t), len(b)) for t, b in msgs))
    sh = [b for t, b in msgs if t == 2][0]
    if sh[0:2] != b"\x03\x03":
        print("非 TLS1.2 ServerHello（版本 %s）；跳过签名验证" % sh[0:2].hex())
        return
    rnd = sh[2:34]
    sid_len = sh[34]
    p = 35 + sid_len
    suite = struct.unpack("!H", sh[p:p + 2])[0]
    extlen = struct.unpack("!H", sh[p + 3:p + 5])[0]
    exts = sh[p + 5:p + 5 + extlen]
    print("ServerHello: 套件=0x%04x 扩展=%s 随机尾8字节=%r"
          % (suite, exts.hex(), rnd[-8:].decode("latin1")))

    cert = [b for t, b in msgs if t == 11][0]
    listlen = struct.unpack("!I", b"\x00" + cert[0:3])[0]
    chain, p = [], 3
    while p + 3 <= len(cert):
        ln = struct.unpack("!I", b"\x00" + cert[p:p + 3])[0]
        chain.append(cert[p + 3:p + 3 + ln])
        p += 3 + ln
    print("Certificate: 声明链长=%d 实际解析出 %d 张 (%s)"
          % (listlen, len(chain), ", ".join(str(len(c)) + "B" for c in chain)))
    for i, der in enumerate(chain):
        s = subprocess.run(["openssl", "x509", "-inform", "DER", "-noout", "-subject", "-serial"],
                           input=der, capture_output=True).stdout.decode(errors="replace").strip()
        print("  证书[%d]: %s" % (i, s.replace("\n", "  ")))
    open("leaf.der", "wb").write(chain[0])
    disc = subprocess.run(["openssl", "x509", "-inform", "DER", "-noout", "-fingerprint", "-sha256"],
                          input=chain[0], capture_output=True).stdout.decode().strip()
    print("叶子指纹:", disc)

    ske = [b for t, b in msgs if t == 12]
    if not ske:
        print("无 ServerKeyExchange —— 该套件为 RSA 密钥交换（无签名）；EAP-TLS 下客户端将用证书加密 pre-master")
        return
    ske = ske[0]
    pklen = ske[3]
    ecdh = ske[:4 + pklen]
    sig_alg = struct.unpack("!H", ske[4 + pklen:6 + pklen])[0]
    siglen = struct.unpack("!H", ske[6 + pklen:8 + pklen])[0]
    sig = ske[8 + pklen:8 + pklen + siglen]
    print("SKE: 组=0x%04x 公钥=%dB sigalg=0x%04x 签名=%dB" % (struct.unpack("!H", ske[1:3])[0], pklen, sig_alg, siglen))

    sh_msg = b"\x02" + struct.pack("!I", len(sh))[1:] + sh
    # RFC 4492/5246：SKE 签名覆盖 client_random || server_random || ServerECDHParams
    rnd_c = ch_msg[6:38]
    rnd_s = sh[2:34]
    md = {0x0401: "sha256", 0x0501: "sha384", 0x0601: "sha512"}.get(sig_alg, "sha256")
    h = hashlib.new(md, rnd_c + rnd_s + ecdh).digest()
    oid = {"sha256": "608648016503040201", "sha384": "608648016503040202",
           "sha512": "608648016503040203"}[md]
    inner = bytes.fromhex("300d0609" + oid + "0500") + bytes([4, len(h)]) + h
    di = bytes([0x30, len(inner)]) + inner

    pub = subprocess.run(["openssl", "x509", "-inform", "DER", "-noout", "-pubkey"],
                         input=chain[0], capture_output=True).stdout
    mod = subprocess.run(["openssl", "rsa", "-pubin", "-noout", "-modulus"],
                         input=pub, capture_output=True).stdout.decode().strip()
    n = int(mod.split("=")[1], 16)
    em = pow(int.from_bytes(sig, "big"), 65537, n).to_bytes((n.bit_length() + 7) // 8, "big")
    print("EM 头 %s / 长度 %d" % (em[:2].hex(), len(em)))
    print("EM 尾部 = %s" % em[-len(di):].hex())
    print("期望 DI = %s" % di.hex())
    ok = em.endswith(di)
    print("SKE 签名验证: %s" % ("通过" if ok else "*** 不匹配 ***"))


if __name__ == "__main__":
    main()
